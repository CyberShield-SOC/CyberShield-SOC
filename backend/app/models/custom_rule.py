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
        CheckConstraint(
            "source IN ('builder', 'sigma')",
            name="ck_custom_rules_source",
        ),
        CheckConstraint("min_count >= 1", name="ck_custom_rules_min_count"),
        Index("ix_custom_rules_rule_id", "rule_id", unique=True),
        # A Sigma rule (by its own id) is imported once.
        Index(
            "uq_custom_rules_source_external_id",
            "source",
            "external_id",
            unique=True,
            postgresql_where=text("external_id IS NOT NULL"),
        ),
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

    min_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
        server_default=text("1"),
    )

    mitre_technique: Mapped[str | None] = mapped_column(
        String(20),
        nullable=True,
    )

    # Where the rule came from: authored in the Rule Builder, or imported
    # from a Sigma rule whose own id is kept in external_id.
    source: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="builder",
        server_default=text("'builder'"),
    )

    external_id: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
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
