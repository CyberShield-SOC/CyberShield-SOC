from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Index, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.models.user import User


class PasswordResetToken(Base):
    """
    A single issued forgot-password token for one account.

    Identified by token_hash — the SHA-256 digest of an opaque token minted
    at /auth/forgot-password and carried only in the emailed reset link
    (never in a JSON response or JS-visible storage). Requesting a new
    token supersedes any still-active one for the same user (marks it
    used) rather than mutating it in place, so the history stays auditable.
    """

    __tablename__ = "password_reset_tokens"

    __table_args__ = (
        Index("ix_password_reset_tokens_user_used", "user_id", "used"),
    )

    id: Mapped[int] = mapped_column(
        BigInteger,
        primary_key=True,
        autoincrement=True,
    )

    user_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    token_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        unique=True,
        index=True,
    )

    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    used: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    user: Mapped[User] = relationship()

    def __repr__(self) -> str:
        return f"PasswordResetToken(id={self.id!r}, user_id={self.user_id!r}, used={self.used!r})"
