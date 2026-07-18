from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    func,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.models.alert import Alert
    from app.models.user import User


class Incident(Base):
    """An investigation created from a persistent security alert."""

    __tablename__ = "incidents"

    __table_args__ = (
        CheckConstraint(
            "priority IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')",
            name="ck_incidents_priority",
        ),
        CheckConstraint(
            "status IN ('OPEN', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE')",
            name="ck_incidents_status",
        ),
        Index("ix_incidents_status", "status"),
        Index("ix_incidents_priority", "priority"),
        Index("ix_incidents_assigned_user_id", "assigned_user_id"),
        Index("ix_incidents_created_by_user_id", "created_by_user_id"),
        Index("ix_incidents_updated_by_user_id", "updated_by_user_id"),
        Index("ix_incidents_created_at", "created_at"),
    )

    id: Mapped[int] = mapped_column(
        BigInteger,
        primary_key=True,
        autoincrement=True,
    )

    source_alert_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey(
            "alerts.id",
            ondelete="RESTRICT",
        ),
        nullable=False,
        unique=True,
    )

    assigned_user_id: Mapped[int | None] = mapped_column(
        BigInteger,
        ForeignKey(
            "users.id",
            ondelete="SET NULL",
        ),
        nullable=True,
    )

    created_by_user_id: Mapped[int | None] = mapped_column(
        BigInteger,
        ForeignKey(
            "users.id",
            ondelete="SET NULL",
        ),
        nullable=True,
    )

    updated_by_user_id: Mapped[int | None] = mapped_column(
        BigInteger,
        ForeignKey(
            "users.id",
            ondelete="SET NULL",
        ),
        nullable=True,
    )

    title: Mapped[str] = mapped_column(
        String(150),
        nullable=False,
    )

    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    priority: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
    )

    status: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="OPEN",
        server_default=text("'OPEN'"),
    )

    opened_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    resolved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    closed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
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

    source_alert: Mapped[Alert] = relationship()

    assigned_user: Mapped[User | None] = relationship(
        foreign_keys=[assigned_user_id],
    )

    created_by_user: Mapped[User | None] = relationship(
        foreign_keys=[created_by_user_id],
    )

    updated_by_user: Mapped[User | None] = relationship(
        foreign_keys=[updated_by_user_id],
    )

    def __repr__(self) -> str:
        return (
            f"Incident(id={self.id!r}, "
            f"source_alert_id={self.source_alert_id!r}, "
            f"priority={self.priority!r}, "
            f"status={self.status!r})"
        )
