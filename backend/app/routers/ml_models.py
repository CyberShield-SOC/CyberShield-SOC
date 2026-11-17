from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.session import get_db
from app.ml.pipeline import InsufficientTrainingDataError
from app.ml.registry import TRAINER_META, get_trainer, list_feature_sets
from app.ml.scoring import feature_deviations
from app.models.ml_model import MLModel
from app.models.user import User
from app.repositories.detection_rule_setting_repository import effective_rule_configs, rule_classes_by_name
from app.repositories.ml_repository import (
    ModelNotFoundError,
    activate_model_version,
    count_feature_snapshots,
    get_active_model,
    list_models,
    list_scored_snapshots,
)
from app.security import require_roles
from app.services.audit import record_audit

router = APIRouter(prefix="/ml", tags=["Machine Learning"])


def _serialize_model(model: MLModel) -> dict:
    return {
        "id": model.id,
        "feature_set": model.feature_set,
        "entity_type": model.entity_type,
        "version": model.version,
        "is_active": model.is_active,
        "feature_names": model.feature_names,
        "sample_count": model.sample_count,
        "params": model.params,
        "trained_at": model.trained_at.isoformat() if model.trained_at else None,
    }


@router.get("/models")
def get_models(
    feature_set: str | None = Query(default=None, max_length=50),
    user: User = Depends(require_roles("Admin", "Analyst", "Viewer")),
    db: Session = Depends(get_db),
):
    """Every trained model version, newest first within each (feature_set,
    entity_type) — the version history behind the "Activate" rollback
    action in the Threat Detection UI's ML models panel."""

    return {"success": True, "models": [_serialize_model(m) for m in list_models(db, feature_set=feature_set)]}


def _pilot_summary(db: Session, feature_set: str) -> tuple[dict, MLModel | None]:
    """Training progress + active model for one registered pilot: the base
    each GET /anomalies row builds on."""

    meta = TRAINER_META[feature_set]
    entity_type = meta["entity_type"]
    sample_count = count_feature_snapshots(db, feature_set=feature_set, entity_type=entity_type)
    active = get_active_model(db, feature_set=feature_set, entity_type=entity_type)
    return {
        "feature_set": feature_set,
        "entity_type": entity_type,
        "min_samples": meta["min_samples"],
        "sample_count": sample_count,
        "ready": sample_count >= meta["min_samples"],
        "active_model": _serialize_model(active) if active else None,
    }, active


@router.post("/models/{feature_set}/train")
def train_model(
    feature_set: str,
    request: Request,
    user: User = Depends(require_roles("Admin")),
    db: Session = Depends(get_db),
):
    """
    Fit and activate a new model version for one feature_set, from
    whatever feature snapshots are stored so far.

    Deliberately synchronous: this project has no background job runner
    (see the feasibility doc's §5.3), so this endpoint blocks for however
    long the fit takes — acceptable for the sample sizes this pilot deals
    with, not something to build a bigger feature_set on without adding
    real background-job infrastructure first.
    """

    trainer = get_trainer(feature_set)
    if trainer is None:
        raise HTTPException(status_code=404, detail=f"No trainer registered for feature_set '{feature_set}'.")

    try:
        saved = trainer(db, created_by=user.id)
    except InsufficientTrainingDataError as exc:
        db.rollback()
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail="The model could not be saved.") from exc

    record_audit(
        db,
        request,
        action="ml.model.train",
        actor=user,
        target_type="ml_model",
        target_id=saved.id,
        target_label=f"{saved.feature_set} v{saved.version}",
        detail={"sample_count": saved.sample_count},
    )
    db.commit()
    return {"success": True, "model": _serialize_model(saved)}


@router.post("/models/{model_id}/activate")
def activate_model(
    model_id: int,
    request: Request,
    user: User = Depends(require_roles("Admin")),
    db: Session = Depends(get_db),
):
    """Roll back (or forward) to a specific previously-trained version."""

    try:
        activated = activate_model_version(db, model_id)
    except ModelNotFoundError as exc:
        db.rollback()
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    record_audit(
        db,
        request,
        action="ml.model.activate",
        actor=user,
        target_type="ml_model",
        target_id=activated.id,
        target_label=f"{activated.feature_set} v{activated.version}",
    )
    db.commit()
    return {"success": True, "model": _serialize_model(activated)}


@router.get("/scores")
def get_scores(
    feature_set: str = Query(max_length=50),
    entity_type: str = Query(default="account", max_length=20),
    below: float | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    user: User = Depends(require_roles("Admin", "Analyst", "Viewer")),
    db: Session = Depends(get_db),
):
    """
    Shadow-mode review queue: the most-anomalous-scoring snapshots for a
    feature_set, regardless of whether any rule actually alerted on them —
    since behavioral_anomaly_* rules default to shadow_mode=True, this is
    the only way to see what a rule *would* flag before deliberately
    turning shadow_mode off for it (feasibility doc §5.5).

    Read-only, so every workspace role can see it: a Viewer should be able
    to read what the models are finding even though only an Admin or
    Analyst can act on it (train, promote out of shadow mode).
    """

    rows = list_scored_snapshots(db, feature_set=feature_set, entity_type=entity_type, below=below, limit=limit)
    return {
        "success": True,
        "scores": [
            {
                "entity_id": row.entity_id,
                "captured_at": row.captured_at.isoformat(),
                "score": row.score,
                "features": row.features,
            }
            for row in rows
        ],
    }


@router.get("/anomalies")
def get_anomaly_overview(
    limit: int = Query(default=5, ge=1, le=50),
    user: User = Depends(require_roles("Admin", "Analyst", "Viewer")),
    db: Session = Depends(get_db),
):
    """
    Everything the dashboard's "Behavioral Anomaly Detection" panel needs,
    for every registered pilot, in one call: training progress, the active
    model, the rule's live score_threshold / shadow_mode, and the `limit`
    most anomalous scored snapshots with the feature deviations that drove
    each score.

    This exists because the rules default to shadow mode: with no alert
    rows to show, the panel was empty even when a trained model had
    already scored real anomalies. Read-only, so open to every role.
    """

    rule_classes = rule_classes_by_name()
    configs = effective_rule_configs(db, settings.detection_rule_config)

    pilots = []
    for feature_set in list_feature_sets():
        summary, active = _pilot_summary(db, feature_set)
        entity_type = summary["entity_type"]
        rule_name = TRAINER_META[feature_set].get("rule_name")
        rule_cls = rule_classes.get(rule_name) if rule_name else None
        config = configs.get(rule_name) if rule_name else None
        params = rule_cls().merge_params(config.params if config else None) if rule_cls else {}
        threshold = params.get("score_threshold")
        threshold = float(threshold) if threshold is not None else None

        # Only what the *active* model produced, for both the ranked scores
        # and the count beside them: other versions' scores aren't comparable
        # and would be explained against the wrong baseline. Matching on
        # model_id (not trained_at) keeps this right after a rollback, when
        # the active model is no longer the newest one.
        scores = []
        scored_count = 0
        if active is not None:
            scored_count = count_feature_snapshots(
                db, feature_set=feature_set, entity_type=entity_type, model_id=active.id
            )
            for row in list_scored_snapshots(
                db, feature_set=feature_set, entity_type=entity_type, model_id=active.id, limit=limit,
            ):
                deviations = sorted(
                    feature_deviations(active, row.features), key=lambda d: abs(d.z_score), reverse=True
                )[:3]
                scores.append({
                    "id": row.id,
                    "entity_id": row.entity_id,
                    "captured_at": row.captured_at.isoformat(),
                    "score": row.score,
                    "below_threshold": threshold is not None and row.score < threshold,
                    "feature_deviations": [
                        {"feature": d.feature, "value": round(d.value, 4), "z_score": round(d.z_score, 2)}
                        for d in deviations
                    ],
                })

        pilots.append({
            **summary,
            "rule_name": rule_name,
            "scored_count": scored_count,
            "rule_enabled": bool(config.enabled) if config is not None else True,
            "score_threshold": threshold,
            "shadow_mode": bool(params.get("shadow_mode", True)),
            "scores": scores,
        })
    return {"success": True, "pilots": pilots}
