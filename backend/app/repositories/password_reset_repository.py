from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.password_reset_token import PasswordResetToken
from app.models.user import User
from app.security import generate_reset_token, lock_auth_user, token_digest


class PasswordResetTokenInvalidError(Exception):
    """A user-facing reset-token failure, with the exact message to return."""


def create_reset_challenge(db: Session, user: User) -> str:
    """
    Invalidate any still-active reset tokens for `user` and issue a new one.

    Returns the plaintext token. Only its digest is persisted; the caller is
    responsible for emailing a link containing it — it is never logged or
    returned in an API response.
    """

    lock_auth_user(db, user.id)
    db.execute(
        update(PasswordResetToken)
        .where(PasswordResetToken.user_id == user.id)
        .where(PasswordResetToken.used.is_(False))
        .values(used=True)
    )

    token = generate_reset_token()
    db.add(
        PasswordResetToken(
            user_id=user.id,
            token_hash=token_digest(token),
            expires_at=datetime.now(timezone.utc)
            + timedelta(minutes=settings.reset_token_expiry_minutes),
            used=False,
        )
    )
    db.flush()
    return token


def consume_reset_token(db: Session, token: str) -> User:
    """
    Validate a presented reset token and mark it used.

    Raises PasswordResetTokenInvalidError with a ready-to-display message if
    the token is unknown, already used, expired, or its account is no
    longer active. The caller commits.
    """

    invalid_message = "This reset link is invalid or has already been used."

    token_hash = token_digest(token)
    user_id = db.scalar(
        select(PasswordResetToken.user_id).where(
            PasswordResetToken.token_hash == token_hash
        )
    )
    if user_id is None:
        raise PasswordResetTokenInvalidError(invalid_message)
    user = lock_auth_user(db, user_id)
    record = db.scalar(
        select(PasswordResetToken)
        .where(PasswordResetToken.token_hash == token_hash)
        .execution_options(populate_existing=True)
    )
    if record is None or record.used:
        raise PasswordResetTokenInvalidError(invalid_message)

    if record.expires_at <= datetime.now(timezone.utc):
        record.used = True
        raise PasswordResetTokenInvalidError(
            "This reset link has expired. Request a new one."
        )

    if user is None or not user.is_active:
        record.used = True
        raise PasswordResetTokenInvalidError(invalid_message)

    record.used = True
    return user
