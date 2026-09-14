from __future__ import annotations

from datetime import datetime

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.models.ml_feature_snapshot import MLFeatureSnapshot
from app.models.ml_model import MLModel


def save_feature_snapshot(
    db: Session,
    *,
    feature_set: str,
    entity_type: str,
    entity_id: str,
    captured_at: datetime,
    features: dict,
    score: float | None = None,
) -> MLFeatureSnapshot:
    """Append one training sample. Flushes but does not commit — same
    convention as the rest of the detection pipeline (see
    app/repositories/alert_repository.py). `score` is set whenever a rule
    scored this event against an active model, null otherwise (no model
    yet) — see app/ml/pipeline.py."""

    row = MLFeatureSnapshot(
        feature_set=feature_set,
        entity_type=entity_type,
        entity_id=entity_id,
        captured_at=captured_at,
        features=features,
        score=score,
    )
    db.add(row)
    db.flush()
    return row


def list_scored_snapshots(
    db: Session,
    *,
    feature_set: str,
    entity_type: str,
    below: float | None = None,
    limit: int = 50,
) -> list[MLFeatureSnapshot]:
    """Most-anomalous-first snapshots with a recorded score — the shadow-mode
    review queue (GET /ml/scores). `below` narrows to scores under a cutoff;
    without it, this is just "lowest scores regardless of any threshold,"
    useful for eyeballing the shape of the distribution."""

    statement = (
        select(MLFeatureSnapshot)
        .where(MLFeatureSnapshot.feature_set == feature_set)
        .where(MLFeatureSnapshot.entity_type == entity_type)
        .where(MLFeatureSnapshot.score.is_not(None))
    )
    if below is not None:
        statement = statement.where(MLFeatureSnapshot.score < below)
    statement = statement.order_by(MLFeatureSnapshot.score.asc()).limit(limit)
    return list(db.scalars(statement).all())


def count_feature_snapshots(db: Session, *, feature_set: str, entity_type: str) -> int:
    return db.scalar(
        select(func.count())
        .select_from(MLFeatureSnapshot)
        .where(MLFeatureSnapshot.feature_set == feature_set)
        .where(MLFeatureSnapshot.entity_type == entity_type)
    ) or 0


def list_feature_snapshots(
    db: Session, *, feature_set: str, entity_type: str, limit: int | None = None
) -> list[MLFeatureSnapshot]:
    """Pooled training population for one (feature_set, entity_type) — every
    entity's history together, oldest first. See the feasibility doc's
    §3.3/§5.2 for why this is pooled rather than one model per entity: a
    per-entity model needs far more history per entity than this project
    can assume it has."""

    statement = (
        select(MLFeatureSnapshot)
        .where(MLFeatureSnapshot.feature_set == feature_set)
        .where(MLFeatureSnapshot.entity_type == entity_type)
        .order_by(MLFeatureSnapshot.captured_at.asc(), MLFeatureSnapshot.id.asc())
    )
    if limit is not None:
        statement = statement.limit(limit)
    return list(db.scalars(statement).all())


def get_active_model(db: Session, *, feature_set: str, entity_type: str) -> MLModel | None:
    return db.scalar(
        select(MLModel)
        .where(MLModel.feature_set == feature_set)
        .where(MLModel.entity_type == entity_type)
        .where(MLModel.is_active.is_(True))
        .order_by(MLModel.version.desc())
        .limit(1)
    )


def list_models(db: Session, *, feature_set: str | None = None) -> list[MLModel]:
    statement = select(MLModel).order_by(MLModel.feature_set, MLModel.entity_type, MLModel.version.desc())
    if feature_set:
        statement = statement.where(MLModel.feature_set == feature_set)
    return list(db.scalars(statement).all())


def save_model(
    db: Session,
    *,
    feature_set: str,
    entity_type: str,
    feature_names: list[str],
    feature_means: dict,
    feature_stds: dict,
    model_bytes: bytes,
    sample_count: int,
    contamination: float | None,
    params: dict,
    created_by: int | None,
    activate: bool = True,
) -> MLModel:
    """Insert a new version and, by default, deactivate every earlier
    version of this (feature_set, entity_type) — one active model at a
    time, so scoring never has to pick between two."""

    next_version = (
        db.scalar(
            select(func.max(MLModel.version))
            .where(MLModel.feature_set == feature_set)
            .where(MLModel.entity_type == entity_type)
        )
        or 0
    ) + 1

    if activate:
        db.execute(
            update(MLModel)
            .where(MLModel.feature_set == feature_set)
            .where(MLModel.entity_type == entity_type)
            .values(is_active=False)
        )

    row = MLModel(
        feature_set=feature_set,
        entity_type=entity_type,
        version=next_version,
        is_active=activate,
        feature_names=feature_names,
        feature_means=feature_means,
        feature_stds=feature_stds,
        model_bytes=model_bytes,
        sample_count=sample_count,
        contamination=contamination,
        params=params,
        created_by=created_by,
    )
    db.add(row)
    db.flush()
    return row


class ModelNotFoundError(Exception):
    """No model row exists with the given id."""


def activate_model_version(db: Session, model_id: int) -> MLModel:
    """Roll back/forward to a specific version: make it the sole active row
    for its (feature_set, entity_type), deactivating every sibling version.
    Scoring always reads whichever row is active — see get_active_model —
    so this takes effect on the very next upload, no redeploy needed."""

    target = db.get(MLModel, model_id)
    if target is None:
        raise ModelNotFoundError(f"No model with id {model_id}.")

    db.execute(
        update(MLModel)
        .where(MLModel.feature_set == target.feature_set)
        .where(MLModel.entity_type == target.entity_type)
        .values(is_active=False)
    )
    target.is_active = True
    db.flush()
    return target
