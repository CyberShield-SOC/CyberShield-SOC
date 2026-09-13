from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Index, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.models.user import User


class OtpVerification(Base):
    """
    A single issued email-OTP challenge for one pending login attempt.

    "The pending login attempt" is identified by pending_token_hash — the
    SHA-256 digest of an opaque token minted at /auth/login and carried only
    in a short-lived HttpOnly cookie (never in a JSON response or JS-visible
    storage). A resend supersedes the previous row for the same
    pending_token_hash (marks it used) and inserts a new one rather than
    mutating it in place, so the attempt/used history stays auditable.
    """

    __tablename__ = "otp_verifications"

    __table_args__ = (
        Index("ix_otp_verifications_pending_token_created", "pending_token_hash", "created_at"),
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

    pending_token_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )

    otp_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )

    remember_me: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
    )

    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    attempt_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
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
        return f"OtpVerification(id={self.id!r}, user_id={self.user_id!r}, used={self.used!r})"
