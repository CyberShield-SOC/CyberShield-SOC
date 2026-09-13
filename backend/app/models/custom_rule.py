from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class CustomRule(Base):
    """A user-authored detection rule that runs alongside the built-in rule pack."""

    __tablename__ = "custom_rules"

    __table_args__ = (
        CheckConstraint(
            "severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')",
            name="ck_custom_rules_severity",
        ),
        CheckConstraint(
            "status IN ('DRAFT', 'ENABLED', 'DISABLED')",
            name="ck_custom_rules_status",
        ),
        Index("ix_custom_rules_rule_id", "rule_id", unique=True),
        Index("ix_custom_rules_status", "status"),
        Index("ix_custom_rules_category", "category"),
    )

    id: Mapped[int] = mapped_column(
        BigInteger,
        primary_key=True,
        autoincrement=True,
    )

    rule_id: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
    )

    name: Mapped[str] = mapped_column(
        String(120),
        nullable=False,
    )

    category: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        server_default=text("'generic_detection'"),
    )

    severity: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
    )

    tactic: Mapped[str | None] = mapped_column(
        String(20),
        nullable=True,
    )

    conditions: Mapped[list] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        server_default=text("'[]'::jsonb"),
    )

    group_by: Mapped[str | None] = mapped_column(
        String(20),
        nullable=True,
    )

    window_seconds: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=600,
        server_default=text("600"),
    )

    actions: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )

    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="DRAFT",
        server_default=text("'DRAFT'"),
    )

    dsl: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    created_by: Mapped[int | None] = mapped_column(
        BigInteger,
        ForeignKey(
            "users.id",
            ondelete="SET NULL",
        ),
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    def __repr__(self) -> str:
        return (
            f"CustomRule(id={self.id!r}, "
            f"rule_id={self.rule_id!r}, "
            f"status={self.status!r})"
        )
