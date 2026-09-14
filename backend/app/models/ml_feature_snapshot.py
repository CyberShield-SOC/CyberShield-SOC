from __future__ import annotations

from datetime import datetime

from sqlalchemy import BigInteger, CheckConstraint, DateTime, Float, Index, String, func, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class MLFeatureSnapshot(Base):
    """
    One numeric feature vector for one event, kept as durable training history.

    Unlike `entity_baselines` (running scalars, overwritten in place — see
    that model's docstring), every row here is retained, because a model
    needs a population of past samples, not just the current running mean.
    `feature_set` names which extractor produced `features` (e.g.
    "login_behavior") and pins the schema those keys follow; a model trained
    on one feature_set only ever scores snapshots from that same set.
    """

    __tablename__ = "ml_feature_snapshots"

    __table_args__ = (
        CheckConstraint(
            "entity_type IN ('source_ip', 'account', 'host')",
            name="ck_ml_feature_snapshots_entity_type",
        ),
        Index(
            "ix_ml_feature_snapshots_set_entity",
            "feature_set", "entity_type", "entity_id", "captured_at",
        ),
        # Training pulls the whole pooled population for a feature_set — see
        # app/ml/train_login_behavior.py. The score index backs shadow-mode
        # review (GET /ml/scores): the lowest scores are the ones worth a
        # human looking at before flipping a rule out of shadow_mode.
        Index("ix_ml_feature_snapshots_set", "feature_set", "entity_type"),
        Index("ix_ml_feature_snapshots_score", "feature_set", "entity_type", "score"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    feature_set: Mapped[str] = mapped_column(String(50), nullable=False)
    entity_type: Mapped[str] = mapped_column(String(20), nullable=False)
    entity_id: Mapped[str] = mapped_column(String(255), nullable=False)
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    features: Mapped[dict] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    # decision_function score against whatever model was active when this
    # snapshot was captured — null until a model exists for this feature_set.
    # This is what makes shadow mode reviewable rather than just silent: an
    # admin can see what a rule *would* have flagged before turning it on.
    score: Mapped[float | None] = mapped_column(Float, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    def __repr__(self) -> str:
        return (
            f"MLFeatureSnapshot(feature_set={self.feature_set!r}, "
            f"entity_id={self.entity_id!r}, captured_at={self.captured_at!r})"
        )
