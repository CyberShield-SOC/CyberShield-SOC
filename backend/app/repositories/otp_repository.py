from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.otp_verification import OtpVerification
from app.models.user import User
from app.repositories.mfa_repository import verify_second_factor
from app.security import (
    generate_otp_code,
    generate_pending_login_token,
    hash_otp_code,
    lock_auth_user,
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


class OtpResendNotApplicableError(Exception):
    """Raised when a resend is asked for a login that uses an authenticator app."""


class OtpVerifyError(Exception):
    """A user-facing OTP verification failure, with the exact message to return."""

    def __init__(
        self, message: str, *, status_code: int = 401, user_id: int | None = None
    ):
        self.message = message
        self.status_code = status_code
        # The account the failed attempt was aimed at, when a pending login
        # was found. Used for the audit trail only, never shown to the caller.
        self.user_id = user_id
        super().__init__(message)


def _latest_otp_for_pending_token(
    db: Session, pending_token_hash: str
) -> OtpVerification | None:
    user_id = db.scalar(
        select(OtpVerification.user_id)
        .where(OtpVerification.pending_token_hash == pending_token_hash)
        .order_by(OtpVerification.created_at.desc(), OtpVerification.id.desc())
        .limit(1)
    )
    if user_id is None:
        return None
    # Lock the stable account before re-reading challenges that a resend can replace.
    lock_auth_user(db, user_id)
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
        .execution_options(populate_existing=True)
    )


def create_otp_challenge(
    db: Session, user: User, *, remember_me: bool, method: str = "email"
) -> tuple[str, str]:
    """
    Start a brand-new pending login for `user`.

    Returns (plaintext_code, plaintext_pending_token). Only their digests are
    persisted; the caller is responsible for emailing the code and setting
    the pending token in a short-lived HttpOnly cookie — neither value is
    ever written to a log or returned to the browser directly.

    With method="totp" no code is generated (the account's authenticator app
    supplies it) and the returned code is an empty string.
    """

    code = generate_otp_code() if method == "email" else ""
    pending_token = generate_pending_login_token()
    now = datetime.now(timezone.utc)

    db.add(
        OtpVerification(
            user_id=user.id,
            pending_token_hash=token_digest(pending_token),
            otp_hash=hash_otp_code(code) if method == "email" else None,
            method=method,
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
    if current.method != "email":
        raise OtpResendNotApplicableError("This sign-in uses an authenticator app.")

    # The cooldown is timed from the last code's issuance regardless of why
    # it's no longer usable (already used, expired, or locked out after too
    # many attempts) — otherwise triggering lockout would be a way to bypass
    # the cooldown and re-arm guessing immediately.
    now = datetime.now(timezone.utc)
    elapsed_seconds = (now - current.created_at).total_seconds()
    if elapsed_seconds < settings.otp_resend_cooldown_seconds:
        raise OtpResendCooldownError(
            retry_after_seconds=int(
                settings.otp_resend_cooldown_seconds - elapsed_seconds
            )
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


def verify_otp_challenge(
    db: Session, pending_token: str, code: str
) -> tuple[User, bool]:
    """verify_login_challenge without the factor: (user, remember_me)."""

    user, remember_me, _factor = verify_login_challenge(db, pending_token, code)
    return user, remember_me


def verify_login_challenge(
    db: Session, pending_token: str, code: str
) -> tuple[User, bool, str]:
    """
    Check `code` against the active challenge for this pending login.

    Returns (user, remember_me, factor) on success, where factor is "email",
    "totp" or "recovery_code". Raises OtpVerifyError with a ready-to-display
    message on any failure. Mutates attempt_count/used on the record in all
    cases; the caller commits. The same attempt limit covers every factor.
    """

    expired_message = "Your verification code has expired. Request a new code."

    pending_hash = token_digest(pending_token)
    record = _latest_otp_for_pending_token(db, pending_hash)
    if record is None:
        raise OtpVerifyError(expired_message)

    if record.used:
        raise OtpVerifyError(expired_message, user_id=record.user_id)

    now = datetime.now(timezone.utc)
    if record.expires_at <= now:
        record.used = True
        raise OtpVerifyError(expired_message, user_id=record.user_id)

    if record.attempt_count >= settings.otp_max_attempts:
        record.used = True
        raise OtpVerifyError(
            "Too many incorrect attempts. Request a new code.", user_id=record.user_id
        )

    user = db.get(User, record.user_id)
    if record.method == "totp":
        # The account row is already locked by _latest_otp_for_pending_token,
        # so the replay counter and recovery codes cannot be raced.
        factor = (
            verify_second_factor(db, user, code)
            if user is not None and user.is_active
            else None
        )
    else:
        factor = (
            "email"
            if len(code) == 6
            and code.isdigit()
            and record.otp_hash is not None
            and verify_otp_code(code, record.otp_hash)
            else None
        )

    if factor is None:
        record.attempt_count += 1
        if record.attempt_count >= settings.otp_max_attempts:
            record.used = True
            raise OtpVerifyError(
                "Too many incorrect attempts. Request a new code.",
                user_id=record.user_id,
            )
        raise OtpVerifyError(
            "Invalid verification code. Please try again.", user_id=record.user_id
        )

    if user is None or not user.is_active:
        record.used = True
        raise OtpVerifyError(expired_message, user_id=record.user_id)

    record.used = True
    return user, record.remember_me, factor
