from __future__ import annotations

import logging
import secrets
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.rate_limit import (
    check_login_failures,
    clear_login_failures,
    limit_by_ip,
    limit_by_user,
    record_login_failure,
)
from app.core.urls import frontend_base_url
from app.db.session import get_db
from app.dispatch.otp_email import get_otp_email_sender
from app.dispatch.reset_email import get_reset_email_sender
from app.models.user import User
from app.repositories.invite_repository import InviteTokenInvalidError, consume_invite, get_invite_details
from app.repositories import mfa_repository
from app.repositories.otp_repository import (
    OtpPendingNotFoundError,
    OtpResendCooldownError,
    OtpResendNotApplicableError,
    OtpVerifyError,
    create_otp_challenge,
    resend_otp_challenge,
    verify_login_challenge,
)
from app.repositories.password_reset_repository import (
    PasswordResetTokenInvalidError,
    consume_reset_token,
    create_reset_challenge,
)
from app.schemas.auth import (
    CurrentUserResponse,
    ForgotPasswordRequest,
    ForgotPasswordResponse,
    LoginRequest,
    LoginResponse,
    MfaCodeRequest,
    MfaDisableRequest,
    RefreshResponse,
    ResetPasswordRequest,
    ResetPasswordResponse,
    TwoFactorRequiredResponse,
    TwoFactorResendResponse,
    TwoFactorVerifyRequest,
)
from app.schemas.invite import AcceptInviteRequest, AcceptInviteResponse, InviteDetailsResponse
from app.security import (
    authenticate_user,
    create_refresh_token,
    current_user,
    find_user_by_id,
    find_user_by_identifier,
    hash_password,
    lock_auth_user,
    mint_access_token,
    revoke_refresh_token,
    revoke_user_sessions,
    rotate_refresh_token,
    verify_password,
)
from app.core.config import settings
from app.services import totp
from app.services.audit import record_audit, user_target
from app.validation import mask_email, password_context_errors


logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["Authentication"])

EMAIL_SEND_FAILURE_MESSAGE = "We couldn't send your verification code. Please try again shortly."
PENDING_EXPIRED_MESSAGE = "Your verification code has expired. Request a new code."

login_rate_limit = limit_by_ip("login", "rate_limit_login_per_minute")
# One shared budget per address across the unauthenticated token endpoints.
auth_rate_limit = limit_by_ip("auth", "rate_limit_auth_per_minute")
# Enrolment and removal each check a code, so they share one per-account budget.
mfa_rate_limit = limit_by_user("mfa", "rate_limit_auth_per_minute")


def user_payload(user: User) -> dict:
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "full_name": user.full_name,
        "is_active": user.is_active,
        "role": user.role.name if user.role else None,
    }


def _set_refresh_cookies(response: Response, refresh_token: str, *, remembered: bool, ttl_minutes: int) -> None:
    csrf_token = secrets.token_urlsafe(32)
    cookie_options = {
        "secure": settings.auth_cookie_secure,
        "samesite": "strict",
        "path": "/",
    }
    if remembered:
        cookie_options["max_age"] = ttl_minutes * 60
    response.set_cookie(
        settings.auth_cookie_name,
        refresh_token,
        httponly=True,
        **cookie_options,
    )
    response.set_cookie(
        settings.auth_csrf_cookie_name,
        csrf_token,
        httponly=False,
        **cookie_options,
    )


def _set_pending_2fa_cookie(response: Response, pending_token: str) -> None:
    response.set_cookie(
        settings.otp_pending_cookie_name,
        pending_token,
        httponly=True,
        secure=settings.auth_cookie_secure,
        samesite="strict",
        path="/",
        max_age=settings.otp_expiry_minutes * 60,
    )


def _clear_pending_2fa_cookie(response: Response) -> None:
    response.delete_cookie(settings.otp_pending_cookie_name, path="/")


@router.post(
    "/login",
    response_model=TwoFactorRequiredResponse,
    dependencies=[Depends(login_rate_limit)],
)
def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    send_otp_email=Depends(get_otp_email_sender),
):
    """
    Verify credentials, then start (never complete) a two-factor login.

    No refresh cookie or access token is issued here — that only happens
    after /auth/2fa/verify succeeds. This endpoint's own response never
    reveals whether the failure was the username or the password, and the
    OTP code itself never appears in the response body.
    """

    # Throttle on the submitted identifier, whether or not it names a real
    # account, so the limit itself cannot be used to enumerate accounts.
    check_login_failures(payload.username)
    user = authenticate_user(db, payload.username, payload.password)
    if user is None:
        record_login_failure(payload.username)
        # The typed identifier is recorded only when it names a real account:
        # people do paste passwords into the username box.
        known = find_user_by_identifier(db, payload.username)
        record_audit(
            db,
            request,
            action="auth.login.password",
            outcome="FAILURE",
            detail={"reason": "invalid_credentials", "account_known": known is not None},
            **(user_target(known) if known is not None else {}),
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )
    clear_login_failures(payload.username)

    # An account with an authenticator app enrolled is asked for its code;
    # nothing is emailed. Everyone else gets the emailed code as before.
    method = "totp" if mfa_repository.active_totp_secret(user) is not None else "email"
    code, pending_token = create_otp_challenge(
        db, user, remember_me=payload.remember_me, method=method
    )

    if method == "email":
        try:
            send_otp_email(to_email=user.email, code=code)
        except Exception as exc:
            db.rollback()
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=EMAIL_SEND_FAILURE_MESSAGE,
            ) from exc

    record_audit(
        db,
        request,
        action="auth.login.password",
        actor=user,
        detail={"second_factor": method},
    )
    db.commit()
    _set_pending_2fa_cookie(response, pending_token)

    return {
        "success": True,
        "requiresTwoFactor": True,
        "email": mask_email(user.email),
        "method": method,
    }


@router.post(
    "/2fa/verify",
    response_model=LoginResponse,
    dependencies=[Depends(auth_rate_limit)],
)
def verify_two_factor(
    payload: TwoFactorVerifyRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    """Complete a pending login: check the OTP, then — and only then — mint
    the real session (refresh cookie + JWT access token)."""

    pending_token = request.cookies.get(settings.otp_pending_cookie_name)
    if not pending_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=PENDING_EXPIRED_MESSAGE)

    try:
        user, remember_me, factor = verify_login_challenge(db, pending_token, payload.code.strip())
    except OtpVerifyError as exc:
        target = db.get(User, exc.user_id) if exc.user_id is not None else None
        record_audit(
            db,
            request,
            action="auth.login.second_factor",
            outcome="FAILURE",
            detail={"reason": exc.message},
            **(user_target(target) if target is not None else {}),
        )
        db.commit()  # persist the attempt_count increment / lockout even on failure
        raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc

    _clear_pending_2fa_cookie(response)
    record_audit(
        db,
        request,
        action="auth.login.second_factor",
        actor=user,
        detail={"remember_me": remember_me, "factor": factor},
    )

    ttl_minutes = (
        settings.auth_remember_ttl_days * 24 * 60
        if remember_me
        else settings.auth_session_ttl_minutes
    )
    # create_refresh_token() commits the session, which also persists this
    # verification's used=True from verify_otp_challenge() above.
    refresh_token = create_refresh_token(db, user, ttl_minutes=ttl_minutes)
    _set_refresh_cookies(response, refresh_token, remembered=remember_me, ttl_minutes=ttl_minutes)

    access_token, expires_in = mint_access_token(user)
    return {
        "success": True,
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": expires_in,
        "user": user_payload(user),
    }


@router.post("/2fa/resend", response_model=TwoFactorResendResponse)
def resend_two_factor(
    request: Request,
    db: Session = Depends(get_db),
    send_otp_email=Depends(get_otp_email_sender),
):
    pending_token = request.cookies.get(settings.otp_pending_cookie_name)
    if not pending_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=PENDING_EXPIRED_MESSAGE)

    try:
        code, user = resend_otp_challenge(db, pending_token)
    except OtpResendCooldownError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Please wait {exc.retry_after_seconds}s before requesting another code.",
        ) from exc
    except OtpResendNotApplicableError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This sign-in uses your authenticator app, so there is no code to resend.",
        ) from exc
    except OtpPendingNotFoundError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=PENDING_EXPIRED_MESSAGE) from exc

    try:
        send_otp_email(to_email=user.email, code=code)
    except Exception as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=EMAIL_SEND_FAILURE_MESSAGE,
        ) from exc

    db.commit()
    return {"success": True, "message": "A new verification code has been sent."}


@router.post("/refresh", response_model=RefreshResponse)
def refresh(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    raw_token = request.cookies.get(settings.auth_cookie_name)
    if raw_token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )

    rotated = rotate_refresh_token(db, raw_token)
    if rotated is None:
        response.delete_cookie(settings.auth_cookie_name, path="/")
        response.delete_cookie(settings.auth_csrf_cookie_name, path="/")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

    user, new_refresh_token, ttl_minutes, remembered = rotated
    _set_refresh_cookies(
        response,
        new_refresh_token,
        remembered=remembered,
        ttl_minutes=ttl_minutes,
    )

    access_token, expires_in = mint_access_token(user)
    return {
        "success": True,
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": expires_in,
        "user": user_payload(user),
    }


@router.post("/logout")
def logout(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    # Logout is idempotent: stale or already-revoked refresh tokens still have
    # their browser cookies cleared and receive the same non-enumerating
    # response.
    raw_token = request.cookies.get(settings.auth_cookie_name)
    if raw_token is not None:
        try:
            user_id = revoke_refresh_token(db, raw_token)
        except HTTPException:
            pass
        else:
            record_audit(
                db, request, action="auth.logout", actor=find_user_by_id(db, user_id)
            )
            db.commit()
    response.delete_cookie(settings.auth_cookie_name, path="/")
    response.delete_cookie(settings.auth_csrf_cookie_name, path="/")
    return {"success": True}


@router.get("/me", response_model=CurrentUserResponse)
def me(user: User = Depends(current_user)):
    return {
        "success": True,
        "user": user_payload(user),
    }


INVALID_MFA_CODE_MESSAGE = "That code is not valid. Check your authenticator app and try again."


def _locked_account(db: Session, user: User) -> User:
    """The caller's own row, locked, so MFA changes cannot interleave."""

    locked = lock_auth_user(db, user.id)
    if locked is None or not locked.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    return locked


@router.get("/mfa")
def mfa_state(user: User = Depends(current_user), db: Session = Depends(get_db)):
    """How this account proves its second factor at sign-in."""

    return {"success": True, **mfa_repository.mfa_status(db, user)}


@router.post("/mfa/totp/setup", dependencies=[Depends(mfa_rate_limit)])
def mfa_totp_setup(user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Start enrolling an authenticator app.

    Returns the shared secret once, as a QR code and as text for manual
    entry. Nothing changes at sign-in until /auth/mfa/totp/enable confirms
    the app is producing the right codes.
    """

    account = _locked_account(db, user)
    if mfa_repository.active_totp_secret(account) is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An authenticator app is already set up. Turn it off before enrolling another.",
        )
    secret = mfa_repository.begin_totp_setup(account)
    db.commit()
    uri = totp.provisioning_uri(secret, account.email)
    return {
        "success": True,
        "secret": secret,
        "otpauth_uri": uri,
        "qr_svg": totp.qr_svg(uri),
        "digits": totp.DIGITS,
        "period_seconds": totp.PERIOD_SECONDS,
    }


@router.post("/mfa/totp/enable", dependencies=[Depends(mfa_rate_limit)])
def mfa_totp_enable(
    payload: MfaCodeRequest,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    """Confirm the pending setup with a code from the app and switch it on.

    The response carries the recovery codes. They are shown this once and
    cannot be read back afterwards.
    """

    account = _locked_account(db, user)
    if mfa_repository.pending_totp_secret(account) is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Start authenticator setup first.",
        )
    recovery_codes = mfa_repository.enable_totp(db, account, payload.code)
    if recovery_codes is None:
        record_audit(
            db, request, action="auth.mfa.enroll", actor=account, outcome="FAILURE",
            detail={"reason": "invalid_code"},
        )
        db.commit()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=INVALID_MFA_CODE_MESSAGE)

    record_audit(db, request, action="auth.mfa.enroll", actor=account, detail={"method": "totp"})
    db.commit()
    return {
        "success": True,
        "recovery_codes": recovery_codes,
        **mfa_repository.mfa_status(db, account),
    }


@router.post("/mfa/totp/disable", dependencies=[Depends(mfa_rate_limit)])
def mfa_totp_disable(
    payload: MfaDisableRequest,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    """Turn the authenticator app off; sign-in returns to emailed codes.

    Needs the account password and a current code (or a recovery code), so a
    borrowed, unlocked session is not enough to weaken the account.
    """

    account = _locked_account(db, user)
    if mfa_repository.active_totp_secret(account) is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="No authenticator app is set up on this account.",
        )
    password_ok = verify_password(payload.password, account.password_hash)
    factor = mfa_repository.verify_second_factor(db, account, payload.code) if password_ok else None
    if factor is None:
        record_audit(
            db, request, action="auth.mfa.disable", actor=account, outcome="FAILURE",
            detail={"reason": "invalid_code" if password_ok else "invalid_password"},
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The password or the code is not correct.",
        )

    mfa_repository.clear_totp(db, account)
    record_audit(db, request, action="auth.mfa.disable", actor=account, detail={"confirmed_with": factor})
    db.commit()
    return {"success": True, **mfa_repository.mfa_status(db, account)}


@router.post("/mfa/recovery-codes", dependencies=[Depends(mfa_rate_limit)])
def mfa_regenerate_recovery_codes(
    payload: MfaCodeRequest,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    """Replace every recovery code with a new set. Needs a current code."""

    account = _locked_account(db, user)
    if mfa_repository.active_totp_secret(account) is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="No authenticator app is set up on this account.",
        )
    if mfa_repository.verify_second_factor(db, account, payload.code) != "totp":
        db.rollback()
        record_audit(
            db, request, action="auth.mfa.recovery_codes", actor=account, outcome="FAILURE",
            detail={"reason": "invalid_code"},
        )
        db.commit()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=INVALID_MFA_CODE_MESSAGE)

    recovery_codes = mfa_repository.issue_recovery_codes(db, account)
    record_audit(db, request, action="auth.mfa.recovery_codes", actor=account)
    db.commit()
    return {
        "success": True,
        "recovery_codes": recovery_codes,
        **mfa_repository.mfa_status(db, account),
    }


GENERIC_RECOVERY_MESSAGE = "If an account matches that email, recovery instructions will be sent."


@router.post(
    "/forgot-password",
    response_model=ForgotPasswordResponse,
    dependencies=[Depends(auth_rate_limit)],
)
def forgot_password(
    payload: ForgotPasswordRequest,
    request: Request,
    db: Session = Depends(get_db),
    send_reset_email=Depends(get_reset_email_sender),
):
    """
    Start a password-reset challenge for the account matching `email`, if any.

    Always returns the same success response regardless of whether the
    email matches an account, whether that account is active, or whether
    the email actually sent — none of that is ever observable from this
    endpoint's response, so it can't be used to enumerate accounts.
    """

    identifier = payload.email.strip().lower()
    user = db.scalar(select(User).where(func.lower(User.email) == identifier))

    if user is not None and user.is_active:
        token = create_reset_challenge(db, user)
        frontend_base = frontend_base_url(request)
        reset_link = f"{frontend_base}/#/reset-password?token={quote(token)}"
        try:
            send_reset_email(to_email=user.email, reset_link=reset_link)
        except Exception as exc:
            # Keep the public response generic so the endpoint cannot be used
            # to discover which email addresses have accounts, but make the
            # operational failure visible in backend/Railway logs. Never log
            # the reset link or token.
            db.rollback()
            logger.error(
                "Password-reset email delivery failed for user_id=%s: %s",
                user.id,
                type(exc).__name__,
            )
        else:
            db.commit()

    record_audit(
        db,
        request,
        action="auth.password_reset.request",
        detail={"account_known": user is not None},
        **(user_target(user) if user is not None else {}),
    )
    db.commit()

    return {"success": True, "message": GENERIC_RECOVERY_MESSAGE}


@router.post(
    "/reset-password",
    response_model=ResetPasswordResponse,
    dependencies=[Depends(auth_rate_limit)],
)
def reset_password(
    payload: ResetPasswordRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """Complete a password reset: consume the token, replace the password,
    and revoke every session issued before the reset."""

    try:
        user = consume_reset_token(db, payload.token)
    except PasswordResetTokenInvalidError as exc:
        record_audit(
            db,
            request,
            action="auth.password_reset.complete",
            outcome="FAILURE",
            detail={"reason": "invalid_or_expired_token"},
        )
        db.commit()  # persist the used=True marked on an expired/stale token
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    context_errors = password_context_errors(
        payload.new_password,
        username=user.username,
        email=user.email,
    )
    if context_errors:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=[
                {
                    "loc": ["body", "new_password"],
                    "msg": message,
                    "type": "value_error",
                }
                for message in context_errors
            ],
        )

    user.password_hash = hash_password(payload.new_password)
    sessions_revoked = revoke_user_sessions(db, user.id)
    record_audit(
        db,
        request,
        action="auth.password_reset.complete",
        actor=find_user_by_id(db, user.id),
        detail={"sessions_revoked": sessions_revoked},
    )
    db.commit()

    return {"success": True, "message": "Your password has been reset. Sign in with your new password."}


@router.get("/invite/{token}", response_model=InviteDetailsResponse)
def invite_details(token: str, db: Session = Depends(get_db)):
    """Validate a presented invite token without consuming it, so the signup
    form can show who invited the account and in what role."""

    try:
        invite = get_invite_details(db, token)
    except InviteTokenInvalidError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    return {
        "email": invite.email,
        "role": invite.role.name,
        "expires_at": invite.expires_at,
    }


@router.post(
    "/accept-invite",
    response_model=AcceptInviteResponse,
    dependencies=[Depends(auth_rate_limit)],
)
def accept_invite(
    payload: AcceptInviteRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """Complete an invite: consume the token and create the account it
    described. Does not mint a session — the new user signs in normally."""

    try:
        invite = consume_invite(db, payload.token)
    except InviteTokenInvalidError as exc:
        record_audit(
            db,
            request,
            action="auth.invite.accept",
            outcome="FAILURE",
            detail={"reason": "invalid_or_expired_token"},
        )
        db.commit()  # persist the used=True marked on an expired/stale token
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    context_errors = password_context_errors(
        payload.password,
        username=payload.username,
        email=invite.email,
    )
    if context_errors:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=[
                {
                    "loc": ["body", "password"],
                    "msg": message,
                    "type": "value_error",
                }
                for message in context_errors
            ],
        )

    new_user = User(
        username=payload.username,
        email=invite.email,
        full_name=payload.full_name,
        password_hash=hash_password(payload.password),
        role_id=invite.role_id,
    )
    db.add(new_user)
    try:
        db.flush()
        record_audit(
            db,
            request,
            action="auth.invite.accept",
            actor=find_user_by_id(db, new_user.id),
            detail={"invited_role": invite.role.name if invite.role else None},
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="That username or email is already in use.",
        ) from exc

    return {"success": True, "message": "Your account is ready. Sign in to continue."}
