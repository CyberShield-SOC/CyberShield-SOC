from __future__ import annotations

import secrets

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.user import User
from app.schemas.auth import (
    CurrentUserResponse,
    LoginRequest,
    LoginResponse,
)
from app.security import (
    authenticate_user,
    bearer_scheme,
    create_access_token,
    current_user,
    revoke_current_session,
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
    access_token = create_access_token(db, user, ttl_minutes=ttl_minutes)
    csrf_token = secrets.token_urlsafe(32)
    cookie_options = {
        "secure": settings.auth_cookie_secure,
        "samesite": "strict",
        "path": "/",
    }
    if payload.remember_me:
        cookie_options["max_age"] = ttl_minutes * 60
    response.set_cookie(
        settings.auth_cookie_name,
        access_token,
        httponly=True,
        **cookie_options,
    )
    response.set_cookie(
        settings.auth_csrf_cookie_name,
        csrf_token,
        httponly=False,
        **cookie_options,
    )

    return {
        "success": True,
        "access_token": access_token,
        "token_type": "bearer",
        "user": user_payload(user),
    }


@router.post("/logout")
def logout(
    request: Request,
    response: Response,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
):
    # Logout is idempotent: stale or already-revoked sessions still have their
    # browser cookies cleared and receive the same non-enumerating response.
    try:
        revoke_current_session(request, credentials, db)
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
