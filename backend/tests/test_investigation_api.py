"""PT-04: guarded transitions, notes, exact actors, and immutable history."""
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError

from app.main import app
from app.models.alert import Alert
from app.models.role import Role
from app.models.user import User
from app.security import current_user


@pytest.fixture
def investigation(db_session):
    suffix = uuid4().hex
    role = db_session.scalar(select(Role).where(Role.name == "Analyst"))
    user = User(role_id=role.id, username=suffix, email=f"{suffix}@example.test", password_hash="unused")
    alert = Alert(upload_id=uuid4(), rule="test", title="Test", description="Evidence must survive", severity="HIGH")
    db_session.add_all([user, alert])
    db_session.commit()
    app.dependency_overrides[current_user] = lambda: user
    yield user, alert.id
    app.dependency_overrides.pop(current_user, None)


def test_states_notes_actor_and_cursor_history(investigation, db_session):
    user, identity = investigation
    with TestClient(app) as client:
        detail = client.get(f"/api/alerts/{identity}/investigation").json()
        assert detail["alert"]["version"] == 1
        response = client.patch(f"/alerts/{identity}/investigation", json={"state": "INVESTIGATING", "expected_version": 1})
        assert response.status_code == 200
        assert response.json()["alert"]["status"] == "REVIEWING"
        assert client.patch(f"/alerts/{identity}/investigation", json={"state": "RESOLVED", "expected_version": 1}).status_code == 409
        note = client.post(f"/alerts/{identity}/investigation/notes", json={"body": "Verified source logs.", "expected_version": 2})
        assert note.status_code == 201
        assert note.json()["version"] == 3
        assert client.patch(f"/alerts/{identity}/investigation", json={"state": "FALSE_POSITIVE", "expected_version": 3}).status_code == 200
        assert client.patch(f"/alerts/{identity}/investigation", json={"state": "ESCALATED"}).status_code == 409
        assert client.patch(f"/alerts/{identity}/investigation", json={"state": "INVESTIGATING", "reason": "New evidence"}).status_code == 200
        page = client.get(f"/alerts/{identity}/investigation/history?limit=2").json()
        later = client.get(f"/alerts/{identity}/investigation/history?after_id={page['next_after_id']}").json()
        events = page["events"] + later["events"]
        assert [e["event_type"] for e in events] == ["STATE_CHANGED", "NOTE_ADDED", "STATE_CHANGED", "STATE_CHANGED"]
        assert all(e["actor_user_id"] == user.id and e["occurred_at"] for e in events)
        assert events[1]["note"] == "Verified source logs."
        assert client.get(f"/alerts/{identity}/investigation/notes").json()["pagination"]["total"] == 1
        event_id = events[0]["id"]
    with pytest.raises(DBAPIError), db_session.begin_nested():
        db_session.execute(text("UPDATE workflow_events SET reason='tampered' WHERE id=:id"), {"id": event_id})
    with pytest.raises(DBAPIError), db_session.begin_nested():
        db_session.execute(text("DELETE FROM workflow_events WHERE id=:id"), {"id": event_id})


def test_old_write_path_is_audited_and_viewer_cannot_mutate(investigation):
    user, identity = investigation
    with TestClient(app) as client:
        assert client.patch(f"/alerts/{identity}", json={"status": "REVIEWING", "severity": "CRITICAL", "expected_version": 1}).status_code == 200
        events = client.get(f"/alerts/{identity}/investigation/history").json()["events"]
        assert len(events) == 2 and all(e["actor_user_id"] == user.id for e in events)
        assert client.patch(f"/alerts/{identity}/investigation", json={"state": "NEW"}).status_code == 409
        assert client.patch(f"/alerts/{identity}", json={"expected_version": 3}).status_code == 422
        before = client.get(f"/alerts/{identity}").json()["alert"]
        assert client.patch(f"/alerts/{identity}", json={"status": "NEW", "severity": "LOW"}).status_code == 409
        assert client.get(f"/alerts/{identity}").json()["alert"] == before
        assert client.post(f"/alerts/{identity}/investigation/notes", json={"body": " "}).status_code == 422
        assert client.patch(f"/alerts/{identity}/investigation", json={"state": "RESOLVED", "actor_user_id": 999}).status_code == 422
        user.role = Role(name="Viewer")
        for method, path, payload in [("patch", "investigation", {"state": "RESOLVED"}), ("post", "investigation/notes", {"body": "x"}), ("post", "escalate", {})]:
            assert getattr(client, method)(f"/alerts/{identity}/{path}", json=payload).status_code == 403
        assert client.get(f"/alerts/{identity}/investigation/history").status_code == 200
        app.dependency_overrides.pop(current_user)
        assert client.get(f"/alerts/{identity}/investigation").status_code == 401


def test_escalation_creates_incident_and_owns_alert(investigation):
    _, identity = investigation
    with TestClient(app) as client:
        assert client.post(f"/alerts/{identity}/escalate").status_code == 201
        assert client.patch(f"/alerts/{identity}/investigation", json={"state": "RESOLVED"}).status_code == 409
        assert client.get(f"/alerts/{identity}/investigation").json()["alert"]["investigation_state"] == "ESCALATED"
        assert client.get("/alerts/99999999/investigation").status_code == 404


@pytest.mark.parametrize("original,target,expected", [
    ("NEW", "INVESTIGATING", 200), ("NEW", "ESCALATED", 200), ("NEW", "RESOLVED", 200), ("NEW", "FALSE_POSITIVE", 200),
    ("INVESTIGATING", "ESCALATED", 200), ("INVESTIGATING", "RESOLVED", 200), ("INVESTIGATING", "FALSE_POSITIVE", 200),
    ("ESCALATED", "INVESTIGATING", 200), ("ESCALATED", "RESOLVED", 200), ("ESCALATED", "FALSE_POSITIVE", 200),
    ("RESOLVED", "INVESTIGATING", 200), ("FALSE_POSITIVE", "INVESTIGATING", 200), ("LEGACY_CLOSED", "INVESTIGATING", 200),
    ("NEW", "NEW", 409), ("INVESTIGATING", "NEW", 409), ("ESCALATED", "NEW", 409),
    ("RESOLVED", "FALSE_POSITIVE", 409), ("FALSE_POSITIVE", "RESOLVED", 409), ("LEGACY_CLOSED", "ESCALATED", 409),
])
def test_documented_investigation_transition_graph(investigation, db_session, original, target, expected):
    from app.services.workflow import PROJECTION
    _, identity = investigation
    alert = db_session.get(Alert, identity)
    alert.investigation_state, alert.status = original, PROJECTION[original]
    db_session.commit()
    with TestClient(app) as client:
        result = client.patch(f"/alerts/{identity}/investigation", json={"state": target, "expected_version": 1, "reason": "Verified supporting activity"})
        assert result.status_code == expected
        persisted = client.get(f"/alerts/{identity}").json()["alert"]
        assert persisted["investigation_state"] == (target if expected == 200 else original)
        assert persisted["version"] == (2 if expected == 200 else 1)
        assert len(client.get(f"/alerts/{identity}/investigation/history").json()["events"]) == (1 if expected == 200 else 0)
