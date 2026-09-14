from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.entity_baseline import EntityBaseline


def get_baseline(
    db: Session, *, entity_type: str, entity_id: str, baseline_key: str
) -> dict | None:
    """Return the stored value for one entity's baseline, or None if never set."""

    row = db.scalar(
        select(EntityBaseline)
        .where(EntityBaseline.entity_type == entity_type)
        .where(EntityBaseline.entity_id == entity_id)
        .where(EntityBaseline.baseline_key == baseline_key)
    )
    return row.value if row is not None else None


def set_baseline(
    db: Session, *, entity_type: str, entity_id: str, baseline_key: str, value: dict
) -> None:
    """Upsert one entity's baseline value. Flushes but does not commit."""

    row = db.scalar(
        select(EntityBaseline)
        .where(EntityBaseline.entity_type == entity_type)
        .where(EntityBaseline.entity_id == entity_id)
        .where(EntityBaseline.baseline_key == baseline_key)
    )
    if row is None:
        db.add(
            EntityBaseline(
                entity_type=entity_type,
                entity_id=entity_id,
                baseline_key=baseline_key,
                value=value,
            )
        )
    else:
        row.value = value
    db.flush()
