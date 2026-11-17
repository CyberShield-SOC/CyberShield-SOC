"""Authenticator-app MFA state for an account: enrolment, checks, recovery codes."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.models.mfa_recovery_code import MfaRecoveryCode
from app.models.user import User
from app.services import totp

logger = logging.getLogger(__name__)


def active_totp_secret(user: User) -> str | None:
    """The account's shared secret, when authenticator MFA is switched on.

    None when it is not enrolled, and also when the stored secret cannot be
    decrypted (the server's OTP_SECRET changed). In that case the account
    signs in with an emailed code again and must re-enrol.
    """

    if user.totp_enabled_at is None or not user.totp_secret:
        return None
    try:
        return totp.decrypt_secret(user.totp_secret)
    except totp.TotpSecretUnreadable:
        logger.error(
            "Authenticator secret for user_id=%s cannot be decrypted; falling back to emailed codes.",
            user.id,
        )
        return None


def mfa_status(db: Session, user: User) -> dict:
    enabled = active_totp_secret(user) is not None
    remaining = 0
    if enabled:
        remaining = db.scalar(
            select(func.count(MfaRecoveryCode.id))
            .where(MfaRecoveryCode.user_id == user.id, MfaRecoveryCode.used_at.is_(None))
        ) or 0
    return {
        "method": "totp" if enabled else "email",
        "totp_enabled": enabled,
        "totp_enabled_at": user.totp_enabled_at.isoformat() if enabled else None,
        "recovery_codes_remaining": remaining,
    }


def begin_totp_setup(user: User) -> str:
    """Store a fresh, not-yet-active secret and return it for the QR code."""

    secret = totp.generate_secret()
    user.totp_secret = totp.encrypt_secret(secret)
    user.totp_enabled_at = None
    user.totp_last_counter = None
    return secret


def pending_totp_secret(user: User) -> str | None:
    if user.totp_enabled_at is not None or not user.totp_secret:
        return None
    try:
        return totp.decrypt_secret(user.totp_secret)
    except totp.TotpSecretUnreadable:
        return None


def issue_recovery_codes(db: Session, user: User) -> list[str]:
    """Replace the account's recovery codes. Returns the plaintext, once."""

    db.execute(delete(MfaRecoveryCode).where(MfaRecoveryCode.user_id == user.id))
    codes = totp.generate_recovery_codes()
    db.add_all(
        MfaRecoveryCode(
            user_id=user.id,
            code_hash=totp.hash_recovery_code(totp.normalize_recovery_code(code)),
        )
        for code in codes
    )
    db.flush()
    return codes


def enable_totp(db: Session, user: User, code: str) -> list[str] | None:
    """Confirm a pending setup with a code from the app. None if it is wrong."""

    secret = pending_totp_secret(user)
    if secret is None:
        return None
    counter = totp.matching_counter(secret, code.strip())
    if counter is None:
        return None
    user.totp_enabled_at = datetime.now(timezone.utc)
    user.totp_last_counter = counter
    return issue_recovery_codes(db, user)


def clear_totp(db: Session, user: User) -> None:
    user.totp_secret = None
    user.totp_enabled_at = None
    user.totp_last_counter = None
    db.execute(delete(MfaRecoveryCode).where(MfaRecoveryCode.user_id == user.id))
    db.flush()


def verify_second_factor(db: Session, user: User, code: str) -> str | None:
    """Check an authenticator code or a recovery code for ``user``.

    Returns "totp" or "recovery_code" and records the use (the time step,
    or the spent recovery code) so neither can be presented twice. The
    caller holds the account row lock and commits.
    """

    secret = active_totp_secret(user)
    if secret is None:
        return None
    code = code.strip()

    counter = totp.matching_counter(secret, code, last_counter=user.totp_last_counter)
    if counter is not None:
        user.totp_last_counter = counter
        return "totp"

    normalized = totp.normalize_recovery_code(code)
    if normalized is None:
        return None
    recovery = db.scalar(
        select(MfaRecoveryCode)
        .where(
            MfaRecoveryCode.user_id == user.id,
            MfaRecoveryCode.code_hash == totp.hash_recovery_code(normalized),
            MfaRecoveryCode.used_at.is_(None),
        )
        .with_for_update()
    )
    if recovery is None:
        return None
    recovery.used_at = datetime.now(timezone.utc)
    return "recovery_code"
