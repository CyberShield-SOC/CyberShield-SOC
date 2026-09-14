from __future__ import annotations

import secrets
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.dispatch.otp_email import get_otp_email_sender
from app.dispatch.reset_email import get_reset_email_sender
from app.models.user import User
from app.repositories.otp_repository import (
    OtpPendingNotFoundError,
    OtpResendCooldownError,
    OtpVerifyError,
    create_otp_challenge,
    resend_otp_challenge,
    verify_otp_challenge,
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
    RefreshResponse,
    ResetPasswordRequest,
    ResetPasswordResponse,
    TwoFactorRequiredResponse,
    TwoFactorResendResponse,
    TwoFactorVerifyRequest,
)
from app.security import (
    authenticate_user,
    create_refresh_token,
    current_user,
    hash_password,
    mint_access_token,
    revoke_refresh_token,
    revoke_user_sessions,
    rotate_refresh_token,
)
from app.core.config import settings
from app.validation import mask_email, password_context_errors


router = APIRouter(prefix="/auth", tags=["Authentication"])

EMAIL_SEND_FAILURE_MESSAGE = "We couldn't send your verification code. Please try again shortly."
PENDING_EXPIRED_MESSAGE = "Your verification code has expired. Request a new code."


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


@router.post("/login", response_model=TwoFactorRequiredResponse)
def login(
    payload: LoginRequest,
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

    user = authenticate_user(db, payload.username, payload.password)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    code, pending_token = create_otp_challenge(db, user, remember_me=payload.remember_me)

    try:
        send_otp_email(to_email=user.email, code=code)
    except Exception as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=EMAIL_SEND_FAILURE_MESSAGE,
        ) from exc

    db.commit()
    _set_pending_2fa_cookie(response, pending_token)

    return {
        "success": True,
        "requiresTwoFactor": True,
        "email": mask_email(user.email),
    }


@router.post("/2fa/verify", response_model=LoginResponse)
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
        user, remember_me = verify_otp_challenge(db, pending_token, payload.code.strip())
    except OtpVerifyError as exc:
        db.commit()  # persist the attempt_count increment / lockout even on failure
        raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc

    _clear_pending_2fa_cookie(response)

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
            revoke_refresh_token(db, raw_token)
        except HTTPException:
            pass
    response.delete_cookie(settings.auth_cookie_name, path="/")
    response.delete_cookie(settings.auth_csrf_cookie_name, path="/")
    return {"success": True}


@router.get("/me", response_model=CurrentUserResponse)
def me(user: User = Depends(current_user)):
    return {
        "success": True,
        "user": user_payload(user),
    }


GENERIC_RECOVERY_MESSAGE = "If an account matches that email, recovery instructions will be sent."


@router.post("/forgot-password", response_model=ForgotPasswordResponse)
def forgot_password(
    payload: ForgotPasswordRequest,
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
        reset_link = (
            f"{settings.frontend_base_url}/#/reset-password?token={quote(token)}"
        )
        try:
            send_reset_email(to_email=user.email, reset_link=reset_link)
        except Exception:
            db.rollback()
        else:
            db.commit()

    return {"success": True, "message": GENERIC_RECOVERY_MESSAGE}


@router.post("/reset-password", response_model=ResetPasswordResponse)
def reset_password(
    payload: ResetPasswordRequest,
    db: Session = Depends(get_db),
):
    """Complete a password reset: consume the token, replace the password,
    and revoke every session issued before the reset."""

    try:
        user = consume_reset_token(db, payload.token)
    except PasswordResetTokenInvalidError as exc:
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
    revoke_user_sessions(db, user.id)
    db.commit()

    return {"success": True, "message": "Your password has been reset. Sign in with your new password."}
