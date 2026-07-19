from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session, joinedload

from app.core.config import settings
from app.db.session import get_db
from app.models.auth_session import AuthSession
from app.models.user import User


password_hasher = PasswordHasher()
bearer_scheme = HTTPBearer(auto_error=False)


def hash_password(password: str) -> str:
    return password_hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return password_hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError):
        return False


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_access_token(
    db: Session,
    user: User,
    *,
    ttl_minutes: int | None = None,
) -> str:
    token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    db.add(
        AuthSession(
            user_id=user.id,
            token_hash=token_digest(token),
            expires_at=now + timedelta(
                minutes=ttl_minutes if ttl_minutes is not None else settings.auth_session_ttl_minutes,
            ),
        )
    )
    db.commit()
    return token


def authenticate_user(db: Session, username: str, password: str) -> User | None:
    identifier = username.strip()
    user = db.scalar(
        select(User)
        .options(joinedload(User.role))
        .where(
            or_(
                User.username == identifier,
                func.lower(User.email) == identifier.lower(),
            )
        )
    )

    if user is None or not user.is_active:
        return None

    if not verify_password(password, user.password_hash):
        return None

    return user


def current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    token = _request_token(request, credentials)
    if token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )

    session = db.scalar(
        select(AuthSession)
        .options(joinedload(AuthSession.user).joinedload(User.role))
        .where(AuthSession.token_hash == token_digest(token))
        .where(AuthSession.revoked_at.is_(None))
        .where(AuthSession.expires_at > datetime.now(timezone.utc))
    )

    if session is None or session.user is None or not session.user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked token",
        )

    return session.user


def revoke_current_session(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None,
    db: Session,
) -> None:
    token = _request_token(request, credentials)
    if token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )

    session = db.scalar(
        select(AuthSession)
        .where(AuthSession.token_hash == token_digest(token))
        .where(AuthSession.revoked_at.is_(None))
    )

    if session is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked token",
        )

    session.revoked_at = datetime.now(timezone.utc)
    db.commit()


def _request_token(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None,
) -> str | None:
    """Prefer an explicit bearer token and otherwise use the browser session."""

    if credentials is not None and credentials.scheme.lower() == "bearer":
        return credentials.credentials

    return request.cookies.get(settings.auth_cookie_name)


def require_roles(*allowed_roles: str):
    allowed = {role.lower() for role in allowed_roles}

    def dependency(user: User = Depends(current_user)) -> User:
        role_name = user.role.name.lower() if user.role else ""
        if role_name not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient role permissions",
            )
        return user

    return dependency
