from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError
from fastapi import Depends, HTTPException, status
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


def create_refresh_token(
    db: Session,
    user: User,
    *,
    ttl_minutes: int | None = None,
) -> str:
    """Mint an opaque, DB-backed refresh token. Only its SHA-256 digest is stored."""

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


def mint_access_token(user: User) -> tuple[str, int]:
    """Mint a short-lived, stateless JWT access token. Not stored server-side."""

    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=settings.jwt_access_ttl_minutes)
    claims = {
        "sub": str(user.id),
        "role": user.role.name if user.role else None,
        "username": user.username,
        "type": "access",
        "iat": now,
        "exp": expires_at,
        "jti": secrets.token_hex(16),
    }
    token = jwt.encode(claims, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)
    return token, settings.jwt_access_ttl_minutes * 60


def decode_access_token(token: str) -> dict:
    return jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])


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
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )

    try:
        claims = decode_access_token(credentials.credentials)
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )

    try:
        user_id = int(claims.get("sub", ""))
    except (TypeError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )

    user = db.scalar(
        select(User).options(joinedload(User.role)).where(User.id == user_id)
    )
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )

    return user


def rotate_refresh_token(
    db: Session,
    raw_token: str,
) -> tuple[User, str, int, bool] | None:
    """Revoke a presented refresh token and issue a new one in its place.

    Preserves the original session's remember-me duration by copying its
    lifespan (expires_at - created_at) onto the new row, so a rotated
    session doesn't silently shrink to the short default TTL. Returns
    (user, new_raw_token, ttl_minutes, remembered) or None if the presented
    token is missing, revoked, expired, or its user is no longer active.
    """

    session = db.scalar(
        select(AuthSession)
        .options(joinedload(AuthSession.user).joinedload(User.role))
        .where(AuthSession.token_hash == token_digest(raw_token))
        .where(AuthSession.revoked_at.is_(None))
        .where(AuthSession.expires_at > datetime.now(timezone.utc))
    )

    if session is None or session.user is None or not session.user.is_active:
        return None

    user = session.user
    ttl_minutes = max(
        1,
        round((session.expires_at - session.created_at).total_seconds() / 60),
    )
    remembered = ttl_minutes > settings.auth_session_ttl_minutes
    session.revoked_at = datetime.now(timezone.utc)

    new_token = create_refresh_token(db, user, ttl_minutes=ttl_minutes)
    return user, new_token, ttl_minutes, remembered


def revoke_refresh_token(db: Session, raw_token: str) -> None:
    session = db.scalar(
        select(AuthSession)
        .where(AuthSession.token_hash == token_digest(raw_token))
        .where(AuthSession.revoked_at.is_(None))
    )

    if session is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked token",
        )

    session.revoked_at = datetime.now(timezone.utc)
    db.commit()


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
