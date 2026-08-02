"""TEST-5 supplement: alert-to-incident workflow coverage not already
exercised by test_api.py's test_complete_persisted_investigation_workflow
and test_note_limit_delete_reuse_and_false_positive_completion.
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
from app.models.alert import Alert
from app.models.role import Role
from app.models.user import User
from app.security import current_user


client = TestClient(app)


@pytest.fixture(autouse=True)
def authenticated_admin(db_session):
    admin_role = db_session.scalar(select(Role).where(Role.name == "Admin"))
    if admin_role is None:
        admin_role = Role(name="Admin", description="Administrator")
        db_session.add(admin_role)
        db_session.flush()

    suffix = uuid4().hex
    admin_user = User(
        role_id=admin_role.id,
        username=f"workflow_admin_{suffix}",
        email=f"workflow_admin_{suffix}@example.test",
        password_hash="not-used",
        is_active=True,
    )
    db_session.add(admin_user)
    db_session.commit()

    app.dependency_overrides[current_user] = lambda: admin_user
    yield admin_user
    app.dependency_overrides.pop(current_user, None)


def make_alert(db_session, **overrides) -> Alert:
    defaults = dict(
        upload_id=uuid4(),
        rule="workflow_test_rule",
        title="Suspicious authentication burst",
        severity="HIGH",
        status="NEW",
        description="Repeated failed authentication attempts from one source.",
        event_count=5,
        time_window_seconds=60,
        matched_line_numbers=[1, 2, 3, 4, 5],
    )
    defaults.update(overrides)
    alert = Alert(**defaults)
    db_session.add(alert)
    db_session.commit()
    return alert


# ── Evidence/reference carry-over from the source alert ─────────────────────

def test_incident_created_without_overrides_inherits_alert_title_description_and_severity(db_session):
    alert = make_alert(db_session, title="Brute-force burst", description="5 failed logins.", severity="CRITICAL")

    created = client.post("/incidents", json={"alert_id": alert.id})

    assert created.status_code == 201
    incident = created.json()["incident"]
    assert incident["title"] == "Brute-force burst"
    assert incident["description"] == "5 failed logins."
    assert incident["priority"] == "CRITICAL"
    assert incident["source_alert_id"] == alert.id


def test_incident_overrides_take_precedence_over_alert_defaults(db_session):
    alert = make_alert(db_session, title="Original alert title", severity="LOW")

    created = client.post(
        "/incidents",
        json={
            "alert_id": alert.id,
            "title": "Analyst-specified incident title",
            "priority": "HIGH",
        },
    )

    assert created.status_code == 201
    incident = created.json()["incident"]
    assert incident["title"] == "Analyst-specified incident title"
    assert incident["priority"] == "HIGH"


def test_promoting_an_alert_to_an_incident_escalates_the_alert_status(db_session):
    alert = make_alert(db_session)
    assert alert.status == "NEW"

    created = client.post("/incidents", json={"alert_id": alert.id})
    assert created.status_code == 201

    alerts_response = client.get("/alerts")
    matching = next(a for a in alerts_response.json()["alerts"] if a["id"] == alert.id)
    assert matching["status"] == "ESCALATED"


# ── Not-found / invalid references ───────────────────────────────────────────

def test_creating_an_incident_for_a_nonexistent_alert_returns_404():
    response = client.post("/incidents", json={"alert_id": 999_999_999})
    assert response.status_code == 404


def test_assigning_a_nonexistent_user_on_incident_creation_returns_404(db_session):
    alert = make_alert(db_session)
    response = client.post(
        "/incidents",
        json={"alert_id": alert.id, "assigned_user_id": 999_999_999},
    )
    assert response.status_code == 404


def test_reassigning_an_incident_to_a_nonexistent_user_returns_404(db_session):
    alert = make_alert(db_session)
    created = client.post("/incidents", json={"alert_id": alert.id})
    incident_id = created.json()["incident"]["id"]

    response = client.patch(
        f"/incidents/{incident_id}",
        json={"assigned_user_id": 999_999_999},
    )
    assert response.status_code == 404


# ── Duplicate promotion prevention ───────────────────────────────────────────

def test_promoting_the_same_alert_twice_is_rejected_even_with_different_details(db_session):
    """Duplicate-prevention must key off the alert, not incidental payload
    differences between the two attempts."""

    alert = make_alert(db_session)
    first = client.post("/incidents", json={"alert_id": alert.id, "title": "First attempt"})
    second = client.post("/incidents", json={"alert_id": alert.id, "title": "Different title, same alert"})

    assert first.status_code == 201
    assert second.status_code == 409


# ── State transitions ─────────────────────────────────────────────────────────

def test_reopening_a_false_positive_incident_clears_resolved_and_closed_timestamps(db_session):
    alert = make_alert(db_session)
    created = client.post("/incidents", json={"alert_id": alert.id})
    incident_id = created.json()["incident"]["id"]

    closed = client.patch(f"/incidents/{incident_id}", json={"status": "FALSE_POSITIVE"})
    assert closed.json()["incident"]["resolved_at"] is not None
    assert closed.json()["incident"]["closed_at"] is not None

    reopened = client.patch(f"/incidents/{incident_id}", json={"status": "OPEN"})

    assert reopened.status_code == 200
    reopened_incident = reopened.json()["incident"]
    assert reopened_incident["resolved_at"] is None
    assert reopened_incident["closed_at"] is None
    assert reopened_incident["status"] == "OPEN"


def test_reopening_a_resolved_incident_to_investigating_clears_resolved_at(db_session):
    alert = make_alert(db_session)
    created = client.post("/incidents", json={"alert_id": alert.id})
    incident_id = created.json()["incident"]["id"]

    resolved = client.patch(f"/incidents/{incident_id}", json={"status": "RESOLVED"})
    assert resolved.json()["incident"]["resolved_at"] is not None

    reopened = client.patch(f"/incidents/{incident_id}", json={"status": "INVESTIGATING"})

    assert reopened.status_code == 200
    assert reopened.json()["incident"]["resolved_at"] is None
    assert reopened.json()["incident"]["status"] == "INVESTIGATING"


def test_patch_incident_rejects_status_values_outside_the_documented_enum(db_session):
    alert = make_alert(db_session)
    created = client.post("/incidents", json={"alert_id": alert.id})
    incident_id = created.json()["incident"]["id"]

    response = client.patch(f"/incidents/{incident_id}", json={"status": "ARCHIVED"})
    assert response.status_code == 422


# ── Authorization for the full workflow chain ────────────────────────────────

def test_viewer_cannot_promote_an_alert_to_an_incident(db_session):
    alert = make_alert(db_session)
    app.dependency_overrides[current_user] = lambda: User(
        id=1, role_id=1, username="viewer1", email="viewer1@example.test",
        password_hash="x", is_active=True, role=Role(id=1, name="Viewer"),
    )

    response = client.post("/incidents", json={"alert_id": alert.id})
    assert response.status_code == 403
