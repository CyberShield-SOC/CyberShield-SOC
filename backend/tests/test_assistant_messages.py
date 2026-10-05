"""Saved AI assistant conversations: per-analyst persistence and clearing."""

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
from app.security import current_user


client = TestClient(app)


def make_user(db_session, role_name: str = "Analyst") -> User:
    role = db_session.scalar(select(Role).where(Role.name == role_name))
    if role is None:
        role = Role(name=role_name, description=role_name)
        db_session.add(role)
        db_session.flush()
    suffix = uuid4().hex
    user = User(
        role_id=role.id,
        username=f"assistant_{role_name.lower()}_{suffix}",
        email=f"assistant_{suffix}@example.test",
        password_hash="not-used",
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    return user


@pytest.fixture
def analyst(db_session):
    user = make_user(db_session)
    app.dependency_overrides[current_user] = lambda: user
    yield user
    app.dependency_overrides.pop(current_user, None)


def test_saved_messages_round_trip_in_order_with_tools(analyst):
    client.post("/assistant/messages", json={"role": "user", "content": "Show failed logins"})
    client.post(
        "/assistant/messages",
        json={"role": "assistant", "content": "Three failures from one host.", "tools_used": ["get_auth_events"]},
    )

    listed = client.get("/assistant/messages").json()["messages"]

    assert [(m["role"], m["content"]) for m in listed] == [
        ("user", "Show failed logins"),
        ("assistant", "Three failures from one host."),
    ]
    assert listed[1]["tools_used"] == ["get_auth_events"]


def test_clear_removes_only_the_callers_saved_messages(db_session, analyst):
    other = make_user(db_session)
    client.post("/assistant/messages", json={"role": "user", "content": "mine"})
    app.dependency_overrides[current_user] = lambda: other
    client.post("/assistant/messages", json={"role": "user", "content": "theirs"})

    assert client.delete("/assistant/messages").status_code == 200
    assert client.get("/assistant/messages").json()["messages"] == []

    app.dependency_overrides[current_user] = lambda: analyst
    remaining = client.get("/assistant/messages").json()["messages"]
    assert [m["content"] for m in remaining] == ["mine"]


def test_conversations_are_private_to_each_analyst(db_session, analyst):
    other = make_user(db_session)
    client.post("/assistant/messages", json={"role": "user", "content": "analyst question"})

    app.dependency_overrides[current_user] = lambda: other
    assert client.get("/assistant/messages").json()["messages"] == []


def test_blank_message_is_rejected(analyst):
    response = client.post("/assistant/messages", json={"role": "user", "content": "   "})
    assert response.status_code == 422
