from __future__ import annotations

import secrets

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.user import User
from app.schemas.auth import (
    CurrentUserResponse,
    LoginRequest,
    LoginResponse,
    RefreshResponse,
)
from app.security import (
    authenticate_user,
    create_refresh_token,
    current_user,
    mint_access_token,
    revoke_refresh_token,
    rotate_refresh_token,
)
from app.core.config import settings


router = APIRouter(prefix="/auth", tags=["Authentication"])


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


@router.post("/login", response_model=LoginResponse)
def login(
    payload: LoginRequest,
    response: Response,
    db: Session = Depends(get_db),
):
    user = authenticate_user(db, payload.username, payload.password)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    ttl_minutes = (
        settings.auth_remember_ttl_days * 24 * 60
        if payload.remember_me
        else settings.auth_session_ttl_minutes
    )
    refresh_token = create_refresh_token(db, user, ttl_minutes=ttl_minutes)
    _set_refresh_cookies(response, refresh_token, remembered=payload.remember_me, ttl_minutes=ttl_minutes)

    access_token, expires_in = mint_access_token(user)
    return {
        "success": True,
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": expires_in,
        "user": user_payload(user),
    }


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
