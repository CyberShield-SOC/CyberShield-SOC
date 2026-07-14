from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class Note(Base):
    """An analyst note attached to a CyberShield incident."""

    __tablename__ = "notes"

    __table_args__ = (
        CheckConstraint(
            "char_length(btrim(body)) > 0",
            name="ck_notes_body_not_blank",
        ),
        Index("ix_notes_incident_id", "incident_id"),
        Index("ix_notes_author_user_id", "author_user_id"),
        Index("ix_notes_created_at", "created_at"),
    )

    id: Mapped[int] = mapped_column(
        BigInteger,
        primary_key=True,
        autoincrement=True,
    )

    incident_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey(
            "incidents.id",
            ondelete="CASCADE",
        ),
        nullable=False,
    )

    author_user_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey(
            "users.id",
            ondelete="RESTRICT",
        ),
        nullable=False,
    )

    body: Mapped[str] = mapped_column(
        Text,
        nullable=False,
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
            f"Note(id={self.id!r}, "
            f"incident_id={self.incident_id!r}, "
            f"author_user_id={self.author_user_id!r})"
        )