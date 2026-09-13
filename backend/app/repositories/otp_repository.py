from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.otp_verification import OtpVerification
from app.models.user import User
from app.security import (
    generate_otp_code,
    generate_pending_login_token,
    hash_otp_code,
    token_digest,
    verify_otp_code,
)


class OtpResendCooldownError(Exception):
    """Raised when a resend is requested before the cooldown window elapses."""

    def __init__(self, retry_after_seconds: int):
        self.retry_after_seconds = max(1, retry_after_seconds)
        super().__init__("Resend cooldown is still active.")


class OtpPendingNotFoundError(Exception):
    """Raised when the pending-login cookie doesn't match any active challenge."""


class OtpVerifyError(Exception):
    """A user-facing OTP verification failure, with the exact message to return."""

    def __init__(self, message: str, *, status_code: int = 401):
        self.message = message
        self.status_code = status_code
        super().__init__(message)


def _latest_otp_for_pending_token(db: Session, pending_token_hash: str) -> OtpVerification | None:
    # Postgres's now()/func.now() is transaction-scoped, not per-statement,
    # so two rows inserted in the same transaction (e.g. login then an
    # immediate resend in one test, or just a fast request path) can get an
    # identical created_at. id DESC breaks that tie deterministically in
    # insertion order, the same pattern used elsewhere in this codebase
    # (e.g. alert_repository.list_alert_records).
    return db.scalar(
        select(OtpVerification)
        .where(OtpVerification.pending_token_hash == pending_token_hash)
        .order_by(OtpVerification.created_at.desc(), OtpVerification.id.desc())
        .limit(1)
    )


def create_otp_challenge(db: Session, user: User, *, remember_me: bool) -> tuple[str, str]:
    """
    Start a brand-new pending login for `user`.

    Returns (plaintext_code, plaintext_pending_token). Only their digests are
    persisted; the caller is responsible for emailing the code and setting
    the pending token in a short-lived HttpOnly cookie — neither value is
    ever written to a log or returned to the browser directly.
    """

    code = generate_otp_code()
    pending_token = generate_pending_login_token()
    now = datetime.now(timezone.utc)

    db.add(
        OtpVerification(
            user_id=user.id,
            pending_token_hash=token_digest(pending_token),
            otp_hash=hash_otp_code(code),
            remember_me=remember_me,
            expires_at=now + timedelta(minutes=settings.otp_expiry_minutes),
            attempt_count=0,
            used=False,
        )
    )
    db.flush()
    return code, pending_token


def resend_otp_challenge(db: Session, pending_token: str) -> tuple[str, User]:
    """
    Invalidate the active OTP for this pending login and issue a new one
    under the same pending token (the cookie is not rotated). Returns
    (plaintext_code, user).
    """

    pending_hash = token_digest(pending_token)
    current = _latest_otp_for_pending_token(db, pending_hash)
    if current is None:
        raise OtpPendingNotFoundError("No pending verification for this session.")

    # The cooldown is timed from the last code's issuance regardless of why
    # it's no longer usable (already used, expired, or locked out after too
    # many attempts) — otherwise triggering lockout would be a way to bypass
    # the cooldown and re-arm guessing immediately.
    now = datetime.now(timezone.utc)
    elapsed_seconds = (now - current.created_at).total_seconds()
    if elapsed_seconds < settings.otp_resend_cooldown_seconds:
        raise OtpResendCooldownError(
            retry_after_seconds=int(settings.otp_resend_cooldown_seconds - elapsed_seconds)
        )

    user = db.get(User, current.user_id)
    if user is None or not user.is_active:
        raise OtpPendingNotFoundError("Account is no longer available.")

    current.used = True  # the previous code stops working immediately

    code = generate_otp_code()
    db.add(
        OtpVerification(
            user_id=user.id,
            pending_token_hash=pending_hash,
            otp_hash=hash_otp_code(code),
            remember_me=current.remember_me,
            expires_at=now + timedelta(minutes=settings.otp_expiry_minutes),
            attempt_count=0,
            used=False,
        )
    )
    db.flush()
    return code, user


def verify_otp_challenge(db: Session, pending_token: str, code: str) -> tuple[User, bool]:
    """
    Check `code` against the active OTP for this pending login.

    Returns (user, remember_me) on success. Raises OtpVerifyError with a
    ready-to-display message on any failure. Mutates attempt_count/used on
    the record in all cases; the caller commits.
    """

    expired_message = "Your verification code has expired. Request a new code."

    pending_hash = token_digest(pending_token)
    record = _latest_otp_for_pending_token(db, pending_hash)
    if record is None:
        raise OtpVerifyError(expired_message)

    if record.used:
        raise OtpVerifyError(expired_message)

    now = datetime.now(timezone.utc)
    if record.expires_at <= now:
        record.used = True
        raise OtpVerifyError(expired_message)

    if record.attempt_count >= settings.otp_max_attempts:
        record.used = True
        raise OtpVerifyError("Too many incorrect attempts. Request a new code.")

    if len(code) != 6 or not code.isdigit() or not verify_otp_code(code, record.otp_hash):
        record.attempt_count += 1
        if record.attempt_count >= settings.otp_max_attempts:
            record.used = True
            raise OtpVerifyError("Too many incorrect attempts. Request a new code.")
        raise OtpVerifyError("Invalid verification code. Please try again.")

    user = db.get(User, record.user_id)
    if user is None or not user.is_active:
        record.used = True
        raise OtpVerifyError(expired_message)

    record.used = True
    return user, record.remember_me
