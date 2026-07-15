from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
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
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    user = authenticate_user(db, payload.username, payload.password)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    return {
        "success": True,
        "access_token": create_access_token(db, user),
        "token_type": "bearer",
        "user": user_payload(user),
    }


@router.post("/logout")
def logout(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
):
    revoke_current_session(credentials, db)
    return {"success": True}


@router.get("/me", response_model=CurrentUserResponse)
def me(user: User = Depends(current_user)):
    return {
        "success": True,
        "user": user_payload(user),
    }
