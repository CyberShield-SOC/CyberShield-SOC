"""PT-05: atomic lifecycle, assignment, linkage, and durable decisions."""
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.main import app
from app.models.alert import Alert
from app.models.role import Role
from app.models.user import User
from app.security import current_user


@pytest.fixture
def scenario(db_session):
    role = db_session.scalar(select(Role).where(Role.name == "Analyst"))
    suffix = uuid4().hex
    user = User(role_id=role.id, username=suffix, email=f"{suffix}@example.test", password_hash="unused")
    alerts = [Alert(upload_id=uuid4(), rule="test", title=f"Alert {i}", description="Source evidence", severity="HIGH") for i in range(3)]
    db_session.add_all([user, *alerts])
    db_session.commit()
    app.dependency_overrides[current_user] = lambda: user
    with TestClient(app) as client:
        created = client.post("/incidents", json={"alert_id": alerts[0].id, "assigned_user_id": user.id})
        assert created.status_code == 201, created.text
        yield client, user, created.json()["incident"]["id"], [a.id for a in alerts]
    app.dependency_overrides.pop(current_user, None)


def test_resolution_reopen_second_resolution_and_note_history(scenario):
    client, user, identity, alerts = scenario
    base = f"/api/incidents/{identity}"
    assert client.post(base + "/alerts", json={"alert_id": alerts[1], "expected_version": 1}).status_code == 201
    assert client.get(base + "/alerts?page_size=1").json()["pagination"]["total"] == 2
    note = client.post(base + "/notes", json={"title": "Review", "body": "Original note"}).json()["note"]
    assert client.patch(f"/notes/{note['id']}", json={"body": "Edited note"}).status_code == 200
    assert client.delete(f"/notes/{note['id']}").status_code == 200
    version = client.get(base).json()["incident"]["version"]
    resolved = client.post(base + "/resolve", json={"reason": "Contained", "note": "Blocked malicious access", "expected_version": version})
    assert resolved.status_code == 200, resolved.text
    first = resolved.json()["incident"]
    assert first["resolved_by_user_id"] == user.id and first["resolved_at"]
    assert all(a["investigation_state"] == "RESOLVED" for a in client.get(base + "/alerts").json()["alerts"])
    assert client.post(base + "/resolve", json={"reason": "Again", "note": "Duplicate"}).status_code == 409
    assert client.patch(base, json={"title": "Reviewed after completion"}).status_code == 200
    assert client.get(base).json()["incident"]["resolved_by_user_id"] == user.id
    assert client.post(base + "/reopen", json={"reason": "New evidence"}).status_code == 200
    assert client.get(base).json()["incident"]["resolved_at"] is None
    assert client.post(base + "/reopen", json={"reason": "Already open"}).status_code == 409
    assert client.post(base + "/resolve", json={"outcome": "FALSE_POSITIVE", "reason": "Expected activity", "note": "Owner verified maintenance"}).status_code == 200
    events = client.get(base + "/history").json()["events"]
    decisions = [e for e in events if e["event_type"] == "RESOLVED"]
    assert len(decisions) == 2
    assert decisions[0]["note"] == "Blocked malicious access"
    assert decisions[0]["after"]["resolved_at"] == first["resolved_at"]
    assert decisions[1]["after"]["status"] == "FALSE_POSITIVE"
    assert any(e["event_type"] == "NOTE_DELETED" and e["before"]["body"] == "Edited note" for e in events)
    assert all(e["actor_user_id"] == user.id and e["occurred_at"] for e in events)


def test_history_pagination_preserves_order_and_entity_isolation(scenario):
    client, _, identity, alerts = scenario
    incident_base = f"/incidents/{identity}"
    alert_base = f"/alerts/{alerts[0]}/investigation"

    assert client.post(alert_base + "/notes", json={"body": "First review"}).status_code == 201
    assert client.post("/incidents", json={"alert_id": alerts[2]}).status_code == 201
    assert client.patch(incident_base, json={"priority": "LOW"}).status_code == 200
    assert client.post(alert_base + "/notes", json={"body": "Second review"}).status_code == 201
    assert client.patch(incident_base, json={"priority": "HIGH"}).status_code == 200

    for path, parent_field, parent_id in (
        (incident_base + "/history", "incident_id", identity),
        (alert_base + "/history", "alert_id", alerts[0]),
    ):
        response = client.get(path, params={"limit": 100})
        assert response.status_code == 200
        expected = response.json()["events"]
        assert len(expected) >= 3
        assert all(event[parent_field] == parent_id for event in expected)

        for page_size in (1, 2, len(expected)):
            after_id = 0
            collected = []
            for _ in range(len(expected)):
                response = client.get(path, params={"after_id": after_id, "limit": page_size})
                assert response.status_code == 200
                page = response.json()
                assert page["success"] is True
                assert 0 < len(page["events"]) <= page_size
                assert all(event["id"] > after_id for event in page["events"])
                collected.extend(page["events"])
                if page["next_after_id"] is None:
                    break
                assert page["next_after_id"] == page["events"][-1]["id"]
                after_id = page["next_after_id"]
            else:
                pytest.fail("History pagination did not reach its last page.")
            assert collected == expected

        empty = client.get(path, params={"after_id": expected[-1]["id"]})
        assert empty.status_code == 200
        assert empty.json() == {"success": True, "events": [], "next_after_id": None}


def test_link_unlink_duplicate_stale_and_invalid_operations(scenario):
    client, user, identity, alerts = scenario
    base = f"/incidents/{identity}"
    assert client.post(base + "/alerts", json={"alert_id": alerts[1]}).status_code == 201
    assert client.post(base + "/alerts", json={"alert_id": alerts[1]}).status_code == 409
    assert client.post("/incidents", json={"alert_id": alerts[1]}).status_code == 409
    assert client.patch(f"/alerts/{alerts[1]}/investigation", json={"state": "RESOLVED"}).status_code == 409
    assert client.delete(base + f"/alerts/{alerts[0]}").status_code == 409
    assert client.delete(base + f"/alerts/{alerts[1]}?expected_version=1").status_code == 409
    assert client.delete(base + f"/alerts/{alerts[1]}").status_code == 200
    assert client.get(f"/alerts/{alerts[1]}").json()["alert"]["investigation_state"] == "INVESTIGATING"
    assert client.delete(base + f"/alerts/{alerts[1]}").status_code == 404
    assert client.post(base + "/resolve", json={"reason": " ", "note": "x"}).status_code == 422
    assert client.patch(base, json={"status": "RESOLVED"}).status_code == 422
    assert client.patch(base, json={"priority": "LOW", "expected_version": 1}).status_code == 409
    assert client.patch(base, json={"assigned_user_id": None}).status_code == 200
    assert client.get(base).json()["incident"]["assigned_user_id"] is None
    assert client.patch(base, json={"updated_by_user_id": 123}).status_code == 422
    assert client.patch(base, json={"expected_version": 3}).status_code == 422
    assert client.post(base + "/reopen", json={"reason": "x"}).status_code == 409


@pytest.mark.parametrize("role_name,active", [("Viewer", True), ("Analyst", False)])
def test_assignment_rejects_ineligible_accounts(scenario, db_session, role_name, active):
    client, _, identity, _ = scenario
    suffix = uuid4().hex
    role = db_session.scalar(select(Role).where(Role.name == role_name))
    user = User(role_id=role.id, username=suffix, email=f"{suffix}@example.test", password_hash="unused", is_active=active)
    db_session.add(user)
    db_session.commit()
    assert client.patch(f"/incidents/{identity}", json={"assigned_user_id": user.id}).status_code == 422
    assert user.id not in {u["id"] for u in client.get("/users/assignable").json()["users"]}


def test_viewer_and_unauthenticated_requests_are_rejected(scenario):
    client, user, identity, alerts = scenario
    user.role = Role(name="Viewer")
    base = f"/incidents/{identity}"
    for path, payload in [("resolve", {"reason": "x", "note": "x"}), ("reopen", {"reason": "x"}), ("alerts", {"alert_id": alerts[1]})]:
        assert client.post(base + "/" + path, json=payload).status_code == 403
    assert client.delete(base + f"/alerts/{alerts[1]}").status_code == 403
    assert client.get(base + "/history").status_code == 200
    app.dependency_overrides.pop(current_user)
    assert client.get(base + "/history").status_code == 401


def test_audit_failure_rolls_back_resolution_and_linked_alerts(scenario, monkeypatch):
    from sqlalchemy.exc import SQLAlchemyError
    from app.services import workflow
    client, _, identity, alerts = scenario
    before = client.get(f"/incidents/{identity}").json()["incident"]
    history = client.get(f"/incidents/{identity}/history").json()["events"]
    def fail(*args, **kwargs):
        raise SQLAlchemyError("synthetic audit failure")
    monkeypatch.setattr(workflow, "record_event", fail)
    assert client.post(f"/incidents/{identity}/resolve", json={"reason": "Contained", "note": "Source reviewed"}).status_code == 500
    after = client.get(f"/incidents/{identity}").json()["incident"]
    assert after == before
    assert client.get(f"/incidents/{identity}/history").json()["events"] == history
    assert client.get(f"/alerts/{alerts[0]}").json()["alert"]["investigation_state"] == "ESCALATED"
