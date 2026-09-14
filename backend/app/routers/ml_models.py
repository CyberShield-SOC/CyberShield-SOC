from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.ml.pipeline import InsufficientTrainingDataError
from app.ml.registry import get_trainer
from app.models.ml_model import MLModel
from app.models.user import User
from app.repositories.ml_repository import (
    ModelNotFoundError,
    activate_model_version,
    list_models,
    list_scored_snapshots,
)
from app.security import require_roles

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


@router.post("/models/{feature_set}/train")
def train_model(
    feature_set: str,
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

    db.commit()
    return {"success": True, "model": _serialize_model(saved)}


@router.post("/models/{model_id}/activate")
def activate_model(
    model_id: int,
    user: User = Depends(require_roles("Admin")),
    db: Session = Depends(get_db),
):
    """Roll back (or forward) to a specific previously-trained version."""

    try:
        activated = activate_model_version(db, model_id)
    except ModelNotFoundError as exc:
        db.rollback()
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    db.commit()
    return {"success": True, "model": _serialize_model(activated)}


@router.get("/scores")
def get_scores(
    feature_set: str = Query(max_length=50),
    entity_type: str = Query(default="account", max_length=20),
    below: float | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    user: User = Depends(require_roles("Admin", "Analyst")),
    db: Session = Depends(get_db),
):
    """
    Shadow-mode review queue: the most-anomalous-scoring snapshots for a
    feature_set, regardless of whether any rule actually alerted on them —
    since behavioral_anomaly_* rules default to shadow_mode=True, this is
    the only way to see what a rule *would* flag before deliberately
    turning shadow_mode off for it (feasibility doc §5.5).
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
