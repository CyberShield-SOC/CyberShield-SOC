from __future__ import annotations

from datetime import datetime

from sqlalchemy import BigInteger, CheckConstraint, DateTime, Index, String, func, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class EntityBaseline(Base):
    """
    Persistent per-entity historical state, carried across uploads.

    One row per (entity_type, entity_id, baseline_key) — e.g.
    ("account", "jdoe", "last_seen_at") or ("account", "jdoe", "recent_hosts").
    `value` is a small JSON payload whose shape is defined by whichever rule
    owns that baseline_key (see app/repositories/baseline_repository.py).
    This is intentionally generic rather than one table per rule, since new
    rules will keep needing small pieces of cross-upload state.
    """

    __tablename__ = "entity_baselines"

    __table_args__ = (
        CheckConstraint(
            "entity_type IN ('source_ip', 'account', 'host')",
            name="ck_entity_baselines_entity_type",
        ),
        Index(
            "ux_entity_baselines_entity_key",
            "entity_type", "entity_id", "baseline_key",
            unique=True,
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    entity_type: Mapped[str] = mapped_column(String(20), nullable=False)
    entity_id: Mapped[str] = mapped_column(String(255), nullable=False)
    baseline_key: Mapped[str] = mapped_column(String(100), nullable=False)
    value: Mapped[dict] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    def __repr__(self) -> str:
        return (
            f"EntityBaseline(entity_type={self.entity_type!r}, "
            f"entity_id={self.entity_id!r}, baseline_key={self.baseline_key!r})"
        )
