from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, func, text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class DetectionRuleSetting(Base):
    """Admin-configurable overrides for a built-in DetectionEngine rule.

    Rows are optional: a rule with no row here still runs using its class
    defaults (optionally seeded by the DETECTION_RULE_CONFIG env var). A row
    only needs to carry the fields an operator actually changed — the rest
    stay NULL and fall back to that same default.
    """

    __tablename__ = "detection_rule_settings"

    rule_name: Mapped[str] = mapped_column(String(60), primary_key=True)

    enabled: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default=text("true"),
    )

    threshold: Mapped[int | None] = mapped_column(Integer, nullable=True)
    fail_threshold: Mapped[int | None] = mapped_column(Integer, nullable=True)
    window_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    success_window_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)

    updated_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    def __repr__(self) -> str:
        return f"DetectionRuleSetting(rule_name={self.rule_name!r}, enabled={self.enabled!r})"
