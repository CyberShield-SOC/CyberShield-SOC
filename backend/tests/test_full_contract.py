"""End-to-end authentication, RBAC, and administration contract tests."""

from __future__ import annotations

import sys
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.main import app
from app.models.role import Role
from app.models.user import User
from app.security import current_user, hash_password


client = TestClient(app)


def fake_user(role_name: str) -> User:
    user = User(
        id=999_999,
        role_id=999_999,
        username=f"contract-{role_name.lower()}",
        email=f"contract-{role_name.lower()}@example.test",
        password_hash="not-returned",
        is_active=True,
    )
    user.role = Role(id=999_999, name=role_name)
    return user


def set_role(role_name: str) -> None:
    app.dependency_overrides[current_user] = lambda: fake_user(role_name)


@pytest.fixture(autouse=True)
def clean_client_and_identity_override():
    client.cookies.clear()
    app.dependency_overrides.pop(current_user, None)
    yield
    client.cookies.clear()
    app.dependency_overrides.pop(current_user, None)


@pytest.mark.parametrize("role_name", ["Admin", "Analyst", "Viewer"])
@pytest.mark.parametrize(
    "path",
    [
        "/alerts",
        "/incidents",
        "/notes",
        "/upload/history",
        "/upload/batches/00000000-0000-4000-8000-000000000001",
        "/upload/latest",
        "/upload/formats",
    ],
)
def test_every_authenticated_role_can_reach_read_endpoints(role_name: str, path: str):
    set_role(role_name)
    response = client.get(path)

    # Empty latest-upload state may be 404, but authorization must succeed.
    assert response.status_code != 403


@pytest.mark.parametrize(
    ("method", "path", "payload", "allowed_roles"),
    [
        ("patch", "/alerts/999999999", {"status": "REVIEWING"}, {"Admin", "Analyst"}),
        ("post", "/incidents", {"alert_id": 999999999}, {"Admin", "Analyst"}),
        ("patch", "/incidents/999999999", {"status": "INVESTIGATING"}, {"Admin", "Analyst"}),
        ("post", "/incidents/999999999/notes", {"body": "Evidence reviewed."}, {"Admin", "Analyst"}),
        ("patch", "/notes/999999999", {"title": "Updated note"}, {"Admin", "Analyst"}),
        ("delete", "/notes/999999999", None, {"Admin", "Analyst"}),
        ("get", "/users", None, {"Admin"}),
        ("get", "/users/roles", None, {"Admin"}),
        ("patch", "/users/999999999", {"full_name": "Updated User"}, {"Admin"}),
        ("patch", "/users/999999999/password", {"new_password": "ReplacementPassphrase-42!"}, {"Admin"}),
        ("post", "/users/999999999/sessions/revoke", None, {"Admin"}),
        ("patch", "/users/999999999/role", {"role": "Viewer"}, {"Admin"}),
        ("patch", "/users/999999999/active", {"is_active": False}, {"Admin"}),
    ],
)
@pytest.mark.parametrize("role_name", ["Admin", "Analyst", "Viewer"])
def test_write_and_admin_permission_matrix(
    method: str,
    path: str,
    payload: dict | None,
    allowed_roles: set[str],
    role_name: str,
):
    set_role(role_name)
    response = client.request(method, path, json=payload)

    if role_name in allowed_roles:
        assert response.status_code != 403
    else:
        assert response.status_code == 403


@pytest.mark.parametrize("role_name", ["Admin", "Analyst"])
def test_admin_and_analyst_can_reach_upload_write_gate(role_name: str):
    set_role(role_name)
    response = client.post(
        "/upload",
        files={"logfile": ("gate.log", b"one test event", "text/plain")},
    )
    assert response.status_code != 403


def test_viewer_cannot_reach_upload_write_gate():
    set_role("Viewer")
    response = client.post(
        "/upload",
        files={"logfile": ("gate.log", b"one test event", "text/plain")},
    )
    assert response.status_code == 403


def ensure_role(db: Session, name: str) -> Role:
    role = db.scalar(select(Role).where(Role.name == name))
    if role is None:
        role = Role(name=name, description=f"{name} test role")
        db.add(role)
        db.flush()
    return role


def test_cookie_and_bearer_login_lifecycle(db_session: Session):
    role = ensure_role(db_session, "Analyst")
    suffix = uuid4().hex[:8]
    username = f"auth-{suffix}"
    password = "ContractPassphrase-42!"
    user = User(
        username=username,
        email=f"{username}@example.test",
        full_name="Contract Analyst",
        password_hash=hash_password(password),
        role_id=role.id,
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()

    rejected = client.post(
        "/auth/login",
        json={"username": username, "password": "incorrect", "remember_me": False},
    )
    login = client.post(
        "/auth/login",
        json={"username": user.email.upper(), "password": password, "remember_me": True},
    )

    assert rejected.status_code == 401
    assert rejected.json()["detail"] == "Invalid username or password"
    assert login.status_code == 200
    assert login.json()["user"]["role"] == "Analyst"
    assert any("Max-Age=" in value for value in login.headers.get_list("set-cookie"))

    cookie_me = client.get("/auth/me")
    assert cookie_me.status_code == 200
    assert cookie_me.json()["user"]["username"] == username

    token = login.json()["access_token"]
    client.cookies.clear()
    bearer_me = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    logout = client.post("/auth/logout", headers={"Authorization": f"Bearer {token}"})
    revoked = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})

    assert bearer_me.status_code == 200
    assert logout.status_code == 200
    assert revoked.status_code == 401


def test_inactive_account_uses_the_same_generic_login_failure(db_session: Session):
    role = ensure_role(db_session, "Viewer")
    suffix = uuid4().hex[:8]
    username = f"inactive-{suffix}"
    password = "InactivePassphrase-42!"
    db_session.add(
        User(
            username=username,
            email=f"{username}@example.test",
            password_hash=hash_password(password),
            role_id=role.id,
            is_active=False,
        )
    )
    db_session.commit()

    response = client.post(
        "/auth/login",
        json={"username": username, "password": password, "remember_me": False},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid username or password"


def test_admin_user_management_lifecycle():
    set_role("Admin")
    suffix = uuid4().hex[:8]
    payload = {
        "username": f"managed-{suffix}",
        "email": f"managed-{suffix}@example.test",
        "full_name": "Managed Test User",
        "password": "ManagedPassphrase-42!",
        "role": "Viewer",
    }

    created = client.post("/users", json=payload)
    duplicate = client.post("/users", json=payload)

    assert created.status_code == 201
    assert duplicate.status_code == 409
    user_id = created.json()["user"]["id"]

    listed = client.get("/users")
    updated_username = f"edited-{suffix}"
    updated_email = f"edited-{suffix}@example.test"
    updated = client.patch(
        f"/users/{user_id}",
        json={
            "username": updated_username,
            "email": updated_email,
            "full_name": "Edited Test User",
            "role": "Analyst",
            "is_active": True,
        },
    )
    managed_login = client.post(
        "/auth/login",
        json={"username": updated_email, "password": payload["password"], "remember_me": False},
    )
    assert managed_login.status_code == 200
    old_token = managed_login.json()["access_token"]
    client.cookies.clear()
    reset = client.patch(
        f"/users/{user_id}/password",
        json={"new_password": "ReplacementPassphrase-42!"},
    )
    revoked = client.post(f"/users/{user_id}/sessions/revoke")
    deactivated = client.patch(f"/users/{user_id}/active", json={"is_active": False})
    reactivated = client.patch(f"/users/{user_id}/active", json={"is_active": True})

    assert any(item["id"] == user_id for item in listed.json()["users"])
    assert updated.status_code == 200
    assert updated.json()["user"]["username"] == updated_username
    assert updated.json()["user"]["email"] == updated_email
    assert updated.json()["user"]["role"] == "Analyst"
    assert "password" not in reset.json()["user"]
    assert "password_hash" not in reset.json()["user"]
    assert reset.status_code == 200
    assert revoked.status_code == 200
    assert deactivated.json()["user"]["is_active"] is False
    assert reactivated.json()["user"]["is_active"] is True

    app.dependency_overrides.pop(current_user, None)
    revoked_session = client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {old_token}"},
    )
    old_password = client.post(
        "/auth/login",
        json={"username": updated_email, "password": payload["password"], "remember_me": False},
    )
    new_password = client.post(
        "/auth/login",
        json={"username": updated_email, "password": "ReplacementPassphrase-42!", "remember_me": False},
    )
    assert old_password.status_code == 401
    assert new_password.status_code == 200
    assert revoked_session.status_code == 401
