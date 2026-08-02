"""TEST-3 supplement: privilege-escalation and account-management guardrails
not yet covered by test_auth_rbac.py / test_full_contract.py / test_jwt_refresh.py.
"""

from __future__ import annotations

import sys
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.main import app
from app.models.role import Role
from app.models.user import User
from app.security import current_user, hash_password


client = TestClient(app)


def fake_user(role_name: str) -> User:
    user = User(
        id=1,
        role_id=1,
        username=f"{role_name.lower()}-esc",
        email=f"{role_name.lower()}-esc@example.test",
        password_hash="not-returned",
        is_active=True,
    )
    user.role = Role(id=1, name=role_name)
    return user


def set_role(role_name: str) -> None:
    app.dependency_overrides[current_user] = lambda: fake_user(role_name)


@pytest.fixture(autouse=True)
def clean_override():
    yield
    app.dependency_overrides.pop(current_user, None)


def ensure_role(db, name: str) -> Role:
    role = db.scalar(select(Role).where(Role.name == name))
    if role is None:
        role = Role(name=name, description=f"{name} test role")
        db.add(role)
        db.flush()
    return role


# ── Only Admin can create accounts (the actual escalation vector) ──────────

@pytest.mark.parametrize("role_name", ["Analyst", "Viewer"])
def test_non_admin_cannot_create_users(role_name):
    set_role(role_name)
    response = client.post(
        "/users",
        json={
            "username": f"escalation-attempt-{uuid4().hex[:8]}",
            "email": f"escalation-{uuid4().hex[:8]}@example.test",
            "password": "AttemptedEscalation-42!",
            "role": "Admin",
        },
    )
    assert response.status_code == 403


def test_non_admin_cannot_assign_admin_role_to_self_via_role_endpoint():
    set_role("Analyst")
    response = client.patch("/users/1/role", json={"role": "Admin"})
    assert response.status_code == 403


def test_non_admin_cannot_reactivate_or_deactivate_accounts():
    set_role("Viewer")
    response = client.patch("/users/1/active", json={"is_active": True})
    assert response.status_code == 403


# ── An unrecognized role name in a JWT/user record must never be treated as
#    implicitly privileged -------------------------------------------------

def test_unrecognized_role_name_is_denied_not_defaulted_to_privileged():
    app.dependency_overrides[current_user] = lambda: fake_user("SuperUser")
    response = client.get("/users")
    assert response.status_code == 403


# ── Last-active-Admin lockout protection (data-integrity / workflow rule) ──

def test_cannot_demote_the_final_active_admin_via_role_endpoint(db_session):
    admin_role = ensure_role(db_session, "Admin")
    analyst_role = ensure_role(db_session, "Analyst")
    suffix = uuid4().hex[:8]

    # Deactivate every other Admin so this test's admin is provably the last one.
    db_session.execute(
        User.__table__.update()
        .where(User.role_id == admin_role.id)
        .values(is_active=False)
    )

    sole_admin = User(
        username=f"sole-admin-{suffix}",
        email=f"sole-admin-{suffix}@example.test",
        password_hash=hash_password("SoleAdminPassphrase-42!"),
        role_id=admin_role.id,
        is_active=True,
    )
    db_session.add(sole_admin)
    db_session.commit()

    app.dependency_overrides[current_user] = lambda: sole_admin

    response = client.patch(f"/users/{sole_admin.id}/role", json={"role": "Analyst"})

    assert response.status_code == 400
    assert "final active Admin" in response.json()["detail"]


def test_cannot_deactivate_the_final_active_admin(db_session):
    admin_role = ensure_role(db_session, "Admin")
    suffix = uuid4().hex[:8]

    db_session.execute(
        User.__table__.update()
        .where(User.role_id == admin_role.id)
        .values(is_active=False)
    )

    sole_admin = User(
        username=f"sole-admin-deact-{suffix}",
        email=f"sole-admin-deact-{suffix}@example.test",
        password_hash=hash_password("SoleAdminPassphrase-42!"),
        role_id=admin_role.id,
        is_active=True,
    )
    db_session.add(sole_admin)
    db_session.commit()

    app.dependency_overrides[current_user] = lambda: sole_admin

    response = client.patch(f"/users/{sole_admin.id}/active", json={"is_active": False})

    assert response.status_code == 400
    assert "final active Admin" in response.json()["detail"]


def test_can_demote_an_admin_when_another_active_admin_remains(db_session):
    admin_role = ensure_role(db_session, "Admin")
    analyst_role = ensure_role(db_session, "Analyst")
    suffix = uuid4().hex[:8]

    admin_one = User(
        username=f"admin-one-{suffix}",
        email=f"admin-one-{suffix}@example.test",
        password_hash=hash_password("AdminOnePassphrase-42!"),
        role_id=admin_role.id,
        is_active=True,
    )
    admin_two = User(
        username=f"admin-two-{suffix}",
        email=f"admin-two-{suffix}@example.test",
        password_hash=hash_password("AdminTwoPassphrase-42!"),
        role_id=admin_role.id,
        is_active=True,
    )
    db_session.add_all([admin_one, admin_two])
    db_session.commit()

    app.dependency_overrides[current_user] = lambda: admin_one

    response = client.patch(f"/users/{admin_two.id}/role", json={"role": "Analyst"})

    assert response.status_code == 200
    assert response.json()["user"]["role"] == "Analyst"
