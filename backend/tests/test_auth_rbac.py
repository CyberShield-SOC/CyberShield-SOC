import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.main import app
from app.models.role import Role
from app.models.user import User
from app.security import current_user, hash_password, verify_password


client = TestClient(app)


@pytest.fixture(autouse=True)
def clean_dependency_overrides():
    clear_user_override()
    yield
    clear_user_override()


def fake_user(role_name: str) -> User:
    user = User(
        id=1,
        role_id=1,
        username=f"{role_name.lower()}1",
        email=f"{role_name.lower()}1@example.test",
        password_hash="not-returned",
        is_active=True,
    )
    user.role = Role(id=1, name=role_name)
    return user


def override_user(role_name: str) -> None:
    app.dependency_overrides[current_user] = lambda: fake_user(role_name)


def clear_user_override() -> None:
    app.dependency_overrides.pop(current_user, None)


def test_password_hashing_and_verification():
    password_hash = hash_password("StrongPassword123!")

    assert password_hash != "StrongPassword123!"
    assert verify_password("StrongPassword123!", password_hash) is True
    assert verify_password("wrong-password", password_hash) is False


def test_protected_endpoint_rejects_missing_token():
    clear_user_override()

    response = client.get("/upload/formats")

    assert response.status_code == 401


def test_viewer_can_read_incidents_but_cannot_create():
    override_user("Viewer")

    read_response = client.get("/incidents")
    write_response = client.post(
        "/incidents",
        json={"alert_id": 1},
    )

    assert read_response.status_code != 403
    assert write_response.status_code == 403


def test_viewer_cannot_add_notes():
    override_user("Viewer")

    response = client.post(
        "/incidents/1/notes",
        json={"body": "Investigating suspicious activity."},
    )

    assert response.status_code == 403


def test_viewer_cannot_update_alerts():
    override_user("Viewer")

    response = client.patch(
        "/alerts/1",
        json={"status": "REVIEWING"},
    )

    assert response.status_code == 403


def test_analyst_cannot_manage_users():
    override_user("Analyst")

    response = client.get("/users")

    assert response.status_code == 403


def test_admin_can_reach_user_management_gate():
    override_user("Admin")

    response = client.get("/users")

    assert response.status_code != 403
