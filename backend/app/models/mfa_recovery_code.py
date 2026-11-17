from __future__ import annotations

from datetime import datetime

from sqlalchemy import BigInteger, DateTime, ForeignKey, String, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class MfaRecoveryCode(Base):
    """One single-use recovery code for an account with authenticator MFA.

    Only a keyed digest is stored. A code is spent by setting ``used_at``;
    the row is kept so the trail of what was used, and when, survives.
    """

    __tablename__ = "mfa_recovery_codes"

    __table_args__ = (
        UniqueConstraint("user_id", "code_hash", name="uq_mfa_recovery_codes_user_code"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)

    user_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    code_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
