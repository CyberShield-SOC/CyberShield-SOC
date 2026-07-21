"""Coverage for the JWT access-token + rotating-refresh-token model.

Complements test_full_contract.py's end-to-end lifecycle test with focused
checks on the pieces that are genuinely new: refresh rotation/replay
detection, CSRF enforcement on the cookie-only endpoints, and JWT signature/
expiry validation.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import jwt
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.config import settings
from app.main import app
from app.models.role import Role
from app.models.user import User
from app.security import hash_password


client = TestClient(app)


@pytest.fixture(autouse=True)
def clean_client():
    client.cookies.clear()
    yield
    client.cookies.clear()


def csrf_headers() -> dict[str, str]:
    token = client.cookies.get(settings.auth_csrf_cookie_name)
    return {"X-CSRF-Token": token} if token else {}


def ensure_role(db: Session, name: str) -> Role:
    role = db.scalar(select(Role).where(Role.name == name))
    if role is None:
        role = Role(name=name, description=f"{name} test role")
        db.add(role)
        db.flush()
    return role


def create_and_login(db_session: Session, *, role_name: str = "Analyst") -> tuple[User, dict]:
    role = ensure_role(db_session, role_name)
    suffix = uuid4().hex[:8]
    username = f"jwt-{suffix}"
    password = "JwtRefreshPassphrase-42!"
    user = User(
        username=username,
        email=f"{username}@example.test",
        password_hash=hash_password(password),
        role_id=role.id,
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()

    login = client.post(
        "/auth/login",
        json={"username": username, "password": password, "remember_me": False},
    )
    assert login.status_code == 200
    return user, login.json()


def test_refresh_rotates_the_token_and_detects_replay(db_session: Session):
    _, login_body = create_and_login(db_session)
    original_refresh_cookie = client.cookies.get(settings.auth_cookie_name)

    first_refresh = client.post("/auth/refresh", headers=csrf_headers())
    assert first_refresh.status_code == 200
    assert first_refresh.json()["access_token"] != login_body["access_token"]
    assert first_refresh.json()["user"]["username"] == login_body["user"]["username"]

    # The cookie jar now holds the rotated token; a second refresh with it
    # succeeds again...
    second_refresh = client.post("/auth/refresh", headers=csrf_headers())
    assert second_refresh.status_code == 200
    assert second_refresh.json()["access_token"] != first_refresh.json()["access_token"]

    # ...but replaying the ORIGINAL (already-rotated-away) refresh token is
    # rejected, since rotation revokes it immediately.
    client.cookies.set(settings.auth_cookie_name, original_refresh_cookie)
    replayed = client.post("/auth/refresh", headers=csrf_headers())
    assert replayed.status_code == 401


def test_refresh_requires_the_matching_csrf_token(db_session: Session):
    create_and_login(db_session)

    rejected = client.post("/auth/refresh")
    assert rejected.status_code == 403

    accepted = client.post("/auth/refresh", headers=csrf_headers())
    assert accepted.status_code == 200


def test_refresh_without_a_cookie_is_unauthorized():
    response = client.post("/auth/refresh")
    assert response.status_code == 401


def test_protected_route_rejects_cookie_only_requests_with_no_bearer_header(db_session: Session):
    """The refresh cookie is real and unexpired, but resource routes now
    require an explicit Authorization header — cookies alone no longer
    authorize API access."""

    create_and_login(db_session)

    response = client.get("/auth/me")
    assert response.status_code == 401


def test_tampered_jwt_signature_is_rejected(db_session: Session):
    user, _ = create_and_login(db_session)

    forged = jwt.encode(
        {
            "sub": str(user.id),
            "role": "Admin",
            "username": user.username,
            "type": "access",
            "iat": datetime.now(timezone.utc),
            "exp": datetime.now(timezone.utc) + timedelta(minutes=10),
        },
        "definitely-the-wrong-secret-but-long-enough-for-hs256",
        algorithm=settings.jwt_algorithm,
    )

    response = client.get("/auth/me", headers={"Authorization": f"Bearer {forged}"})
    assert response.status_code == 401


def test_expired_jwt_is_rejected(db_session: Session):
    user, _ = create_and_login(db_session)

    expired = jwt.encode(
        {
            "sub": str(user.id),
            "role": "Analyst",
            "username": user.username,
            "type": "access",
            "iat": datetime.now(timezone.utc) - timedelta(minutes=20),
            "exp": datetime.now(timezone.utc) - timedelta(minutes=1),
        },
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
    )

    response = client.get("/auth/me", headers={"Authorization": f"Bearer {expired}"})
    assert response.status_code == 401


def test_malformed_bearer_token_is_rejected():
    response = client.get("/auth/me", headers={"Authorization": "Bearer not-a-real-jwt"})
    assert response.status_code == 401
