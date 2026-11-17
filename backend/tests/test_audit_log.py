"""The platform audit trail: what gets recorded, and who may read it."""

from __future__ import annotations

import sys
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.dispatch.otp_email import get_otp_email_sender
from app.main import app
from app.models.audit_event import AuditEvent
from app.models.role import Role
from app.models.user import User
from app.security import current_user, hash_password


client = TestClient(app)
PASSWORD = "AuditTrailPassphrase-42!"


@pytest.fixture(autouse=True)
def clean_state():
    client.cookies.clear()
    yield
    client.cookies.clear()
    app.dependency_overrides.pop(current_user, None)
    app.dependency_overrides.pop(get_otp_email_sender, None)


def ensure_role(db: Session, name: str) -> Role:
    role = db.scalar(select(Role).where(Role.name == name))
    if role is None:
        role = Role(name=name, description=f"{name} test role")
        db.add(role)
        db.flush()
    return role


def create_user(db: Session, role_name: str = "Analyst") -> User:
    role = ensure_role(db, role_name)
    username = f"audit-{uuid4().hex[:8]}"
    user = User(
        username=username,
        email=f"{username}@example.test",
        full_name=f"Audit {role_name}",
        password_hash=hash_password(PASSWORD),
        role_id=role.id,
        is_active=True,
    )
    db.add(user)
    db.commit()
    user.role = role
    return user


def act_as(user: User) -> None:
    app.dependency_overrides[current_user] = lambda: user


def events_for(db: Session, action: str) -> list[AuditEvent]:
    db.expire_all()
    return list(
        db.scalars(
            select(AuditEvent).where(AuditEvent.action == action).order_by(AuditEvent.id)
        )
    )


def capture_otp() -> dict:
    sent: dict = {}

    def sender(*, to_email: str, code: str) -> None:
        sent["code"] = code

    app.dependency_overrides[get_otp_email_sender] = lambda: sender
    return sent


def test_a_full_sign_in_records_both_steps_against_the_account(db_session):
    user = create_user(db_session)
    sent = capture_otp()
    before = len(events_for(db_session, "auth.login.second_factor"))

    login = client.post("/auth/login", json={"username": user.username, "password": PASSWORD})
    verify = client.post("/auth/2fa/verify", json={"code": sent["code"]})

    assert login.status_code == 200 and verify.status_code == 200
    password_step = events_for(db_session, "auth.login.password")[-1]
    second_factor = events_for(db_session, "auth.login.second_factor")
    assert len(second_factor) == before + 1
    for event in (password_step, second_factor[-1]):
        assert event.outcome == "SUCCESS"
        assert event.actor_user_id == user.id
        assert event.actor_name == "Audit Analyst"
        assert event.actor_role == "Analyst"
    assert password_step.user_agent == "testclient"


def test_a_wrong_password_is_recorded_as_a_failure_naming_the_targeted_account(db_session):
    user = create_user(db_session)

    response = client.post("/auth/login", json={"username": user.username, "password": "nope"})

    assert response.status_code == 401
    event = events_for(db_session, "auth.login.password")[-1]
    assert event.outcome == "FAILURE"
    assert event.actor_user_id is None and event.actor_name == "Anonymous"
    assert (event.target_type, event.target_id, event.target_label) == (
        "user",
        str(user.id),
        user.username,
    )
    assert event.detail == {"reason": "invalid_credentials", "account_known": True}


def test_a_failed_sign_in_for_an_unknown_identifier_never_stores_what_was_typed(db_session):
    typed = f"Hunter2-{uuid4().hex}"  # a password pasted into the username box

    client.post("/auth/login", json={"username": typed, "password": "whatever"})

    event = events_for(db_session, "auth.login.password")[-1]
    assert event.outcome == "FAILURE"
    assert event.target_label is None
    assert event.detail == {"reason": "invalid_credentials", "account_known": False}
    assert typed not in str(event.detail)


def test_a_wrong_second_factor_code_is_recorded_against_the_account(db_session):
    user = create_user(db_session)
    sent = capture_otp()
    client.post("/auth/login", json={"username": user.username, "password": PASSWORD})
    wrong = "000000" if sent["code"] != "000000" else "111111"

    response = client.post("/auth/2fa/verify", json={"code": wrong})

    assert response.status_code == 401
    event = events_for(db_session, "auth.login.second_factor")[-1]
    assert event.outcome == "FAILURE"
    assert event.target_id == str(user.id)
    assert wrong not in str(event.detail)


def test_admin_account_changes_are_recorded_with_before_and_after(db_session):
    admin = create_user(db_session, "Admin")
    target = create_user(db_session, "Analyst")
    ensure_role(db_session, "Viewer")
    db_session.commit()
    act_as(admin)

    role_change = client.patch(f"/users/{target.id}/role", json={"role": "Viewer"})
    disable = client.patch(f"/users/{target.id}/active", json={"is_active": False})

    assert role_change.status_code == 200 and disable.status_code == 200
    role_event = events_for(db_session, "user.role.change")[-1]
    active_event = events_for(db_session, "user.active.change")[-1]
    assert role_event.actor_user_id == admin.id and role_event.actor_role == "Admin"
    assert role_event.target_label == target.username
    assert role_event.detail == {"from": "Analyst", "to": "Viewer"}
    assert active_event.detail == {"from": True, "to": False}


def test_a_password_reset_by_an_admin_is_recorded_without_the_password(db_session):
    admin = create_user(db_session, "Admin")
    target = create_user(db_session, "Analyst")
    act_as(admin)
    new_password = "ReplacementPassphrase-97!"

    response = client.patch(f"/users/{target.id}/password", json={"new_password": new_password})

    assert response.status_code == 200
    event = events_for(db_session, "user.password.reset")[-1]
    assert event.target_id == str(target.id)
    assert new_password not in str(event.detail)
    assert set(event.detail) == {"sessions_revoked"}


def test_a_rejected_change_leaves_no_audit_event(db_session):
    analyst = create_user(db_session, "Analyst")
    target = create_user(db_session, "Analyst")
    act_as(analyst)
    before = len(events_for(db_session, "user.active.change"))

    response = client.patch(f"/users/{target.id}/active", json={"is_active": False})

    assert response.status_code == 403
    assert len(events_for(db_session, "user.active.change")) == before


def test_threat_feed_import_and_removal_are_recorded(db_session):
    admin = create_user(db_session, "Admin")
    act_as(admin)
    source = f"audit-feed-{uuid4().hex[:6]}"

    imported = client.post(
        "/threat-intel/feeds",
        json={"source": source, "content": "203.0.113.5\nevil.example\nnot an indicator!!\n"},
    )
    removed = client.delete(f"/threat-intel/feeds/{source}")

    assert imported.status_code == 200 and removed.status_code == 200
    import_event = [e for e in events_for(db_session, "threat_intel.feed.import") if e.target_label == source][-1]
    delete_event = [e for e in events_for(db_session, "threat_intel.feed.delete") if e.target_label == source][-1]
    assert import_event.detail["imported"] == 2
    assert delete_event.detail == {"removed": 2}


def test_only_admins_can_read_the_audit_trail(db_session):
    for role_name, expected in (("Viewer", 403), ("Analyst", 403), ("Admin", 200)):
        act_as(create_user(db_session, role_name))
        assert client.get("/audit/events").status_code == expected

    app.dependency_overrides.pop(current_user, None)
    assert client.get("/audit/events").status_code == 401


def test_the_audit_trail_has_no_write_endpoints(db_session):
    act_as(create_user(db_session, "Admin"))

    for method in ("post", "patch", "put", "delete"):
        assert getattr(client, method)("/audit/events").status_code == 405
        assert getattr(client, method)("/audit/events/1").status_code in {404, 405}


def test_listing_is_newest_first_filterable_and_paged(db_session):
    admin = create_user(db_session, "Admin")
    target = create_user(db_session, "Analyst")
    act_as(admin)
    for active in (False, True, False):
        client.patch(f"/users/{target.id}/active", json={"is_active": active})
    client.post("/auth/login", json={"username": target.username, "password": "nope"})

    everything = client.get("/audit/events", params={"limit": 200}).json()
    users_only = client.get("/audit/events", params={"category": "user", "limit": 200}).json()
    failures = client.get("/audit/events", params={"outcome": "FAILURE", "limit": 200}).json()
    by_actor = client.get("/audit/events", params={"actor": "audit admin", "limit": 200}).json()
    first_page = client.get("/audit/events", params={"category": "user", "limit": 2}).json()
    second_page = client.get(
        "/audit/events",
        params={"category": "user", "limit": 2, "before_id": first_page["next_before_id"]},
    ).json()

    ids = [event["id"] for event in everything["events"]]
    assert ids == sorted(ids, reverse=True)
    assert {event["action"].split(".")[0] for event in users_only["events"]} == {"user"}
    assert {event["outcome"] for event in failures["events"]} == {"FAILURE"}
    assert all("audit admin" in event["actor_name"].lower() for event in by_actor["events"])
    assert len(first_page["events"]) == 2
    assert first_page["next_before_id"] == first_page["events"][-1]["id"]
    assert second_page["events"][0]["id"] < first_page["events"][-1]["id"]
    assert "user" in everything["categories"]


def test_an_unknown_category_is_rejected(db_session):
    act_as(create_user(db_session, "Admin"))

    assert client.get("/audit/events", params={"category": "nonsense"}).status_code == 422
