from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Index, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.models.role import Role
    from app.models.user import User


class InviteToken(Base):
    """
    A single issued account-invite for one email address.

    Identified by token_hash — the SHA-256 digest of an opaque token minted
    at POST /users/invites — carried only in the emailed signup link (never
    in a JSON response or JS-visible storage). Inviting the same email again
    supersedes any still-active invite (marks it used) rather than mutating
    it in place, so the history stays auditable. ``revoked`` is distinct
    from ``used``: it marks an Admin's explicit cancellation rather than a
    consumed or superseded invite, so the Users page can tell them apart.
    """

    __tablename__ = "invite_tokens"

    __table_args__ = (
        Index("ix_invite_tokens_email_used_revoked", "email", "used", "revoked"),
    )

    id: Mapped[int] = mapped_column(
        BigInteger,
        primary_key=True,
        autoincrement=True,
    )

    email: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
    )

    role_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("roles.id", ondelete="RESTRICT"),
        nullable=False,
    )

    invited_by_user_id: Mapped[int | None] = mapped_column(
        BigInteger,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
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

    revoked: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    role: Mapped[Role] = relationship()
    invited_by: Mapped[User | None] = relationship()

    def __repr__(self) -> str:
        return (
            f"InviteToken(id={self.id!r}, email={self.email!r}, "
            f"used={self.used!r}, revoked={self.revoked!r})"
        )
