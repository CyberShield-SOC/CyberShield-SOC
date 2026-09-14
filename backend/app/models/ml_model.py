from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class MLModel(Base):
    """
    One fitted, versioned model for one (feature_set, entity_type) pair.

    Trained offline (see app/ml/train_login_behavior.py) — never inside the
    request path. `feature_names` pins the exact order/shape of the vector
    the model expects, so scoring code can refuse to use a model whose
    feature schema has drifted rather than silently feeding it garbage.
    `feature_means`/`feature_stds` are the training set's own per-feature
    stats, kept purely for explainability: scoring reports which feature was
    how many standard deviations from "normal," not just a raw score.
    Only one row per (feature_set, entity_type) is `is_active` at a time —
    that is the model scoring actually uses. A feature_set with no active
    row has never been trained, which is this project's stand-in for shadow
    mode: snapshots accumulate, nothing alerts, until someone deliberately
    runs the training script.
    """

    __tablename__ = "ml_models"

    __table_args__ = (
        UniqueConstraint("feature_set", "entity_type", "version", name="uq_ml_models_set_entity_version"),
        Index("ix_ml_models_active", "feature_set", "entity_type", "is_active"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    feature_set: Mapped[str] = mapped_column(String(50), nullable=False)
    entity_type: Mapped[str] = mapped_column(String(20), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    feature_names: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    feature_means: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    feature_stds: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    model_bytes: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)

    sample_count: Mapped[int] = mapped_column(Integer, nullable=False)
    contamination: Mapped[float | None] = mapped_column(Float, nullable=True)
    params: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    trained_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    created_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    def __repr__(self) -> str:
        return (
            f"MLModel(feature_set={self.feature_set!r}, entity_type={self.entity_type!r}, "
            f"version={self.version!r}, is_active={self.is_active!r})"
        )
