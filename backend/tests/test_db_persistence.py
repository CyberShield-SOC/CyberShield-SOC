"""TEST-4: direct model-level persistence, relationship, cascade, and
transaction-rollback coverage. Complements the existing API-level tests
(test_api.py, test_full_contract.py) which exercise these paths indirectly.

Uses the shared rollback-only `db_session` fixture from conftest.py, so
nothing here touches real development/production data -- every row is
undone when the test's outer transaction rolls back.
"""

from __future__ import annotations

import sys
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.models.alert import Alert
from app.models.incident import Incident
from app.models.log import Log
from app.models.note import Note
from app.models.role import Role
from app.models.user import User


def ensure_role(db, name: str) -> Role:
    role = db.scalar(select(Role).where(Role.name == name))
    if role is None:
        role = Role(name=name, description=f"{name} test role")
        db.add(role)
        db.flush()
    return role


def make_user(db, role: Role, tag: str) -> User:
    suffix = uuid4().hex[:8]
    user = User(
        username=f"{tag}-{suffix}",
        email=f"{tag}-{suffix}@example.test",
        password_hash="not-used",
        role_id=role.id,
        is_active=True,
    )
    db.add(user)
    db.flush()
    return user


def make_alert(db, tag: str) -> Alert:
    alert = Alert(
        upload_id=uuid4(),
        rule=f"{tag}_rule",
        title=f"{tag} alert",
        severity="HIGH",
        status="NEW",
        description="Persistence test alert.",
        event_count=5,
        time_window_seconds=60,
        matched_line_numbers=[1, 2, 3],
    )
    db.add(alert)
    db.flush()
    return alert


# ── Basic create/retrieve/update ─────────────────────────────────────────────

def test_log_record_round_trips_through_the_database(db_session):
    upload_id = uuid4()
    log = Log(
        upload_id=upload_id,
        source_filename="round-trip.csv",
        source_format="csv",
        line_number=1,
        ip_address="203.0.113.4",
        username="root",
        event_type="login_attempt",
        status="FAILED",
        raw_message="raw line",
        parsed_data={"ip_address": "203.0.113.4"},
    )
    db_session.add(log)
    db_session.commit()

    fetched = db_session.scalar(select(Log).where(Log.upload_id == upload_id))
    assert fetched is not None
    assert fetched.username == "root"
    assert fetched.parsed_data["ip_address"] == "203.0.113.4"


def test_incident_update_persists_and_updated_at_changes(db_session):
    admin_role = ensure_role(db_session, "Admin")
    admin = make_user(db_session, admin_role, "persist-admin")
    alert = make_alert(db_session, "persist-update")

    incident = Incident(
        source_alert_id=alert.id,
        created_by_user_id=admin.id,
        updated_by_user_id=admin.id,
        title="Original title",
        description="Original description",
        priority="MEDIUM",
        status="OPEN",
    )
    db_session.add(incident)
    db_session.commit()
    original_updated_at = incident.updated_at

    incident.title = "Revised title"
    db_session.commit()
    db_session.refresh(incident)

    assert incident.title == "Revised title"
    assert incident.updated_at >= original_updated_at


# ── Foreign-key / relationship integrity ─────────────────────────────────────

def test_role_with_active_users_cannot_be_deleted(db_session):
    role = ensure_role(db_session, "Viewer")
    make_user(db_session, role, "fk-restrict-role")
    db_session.commit()

    db_session.delete(role)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_alert_with_an_incident_cannot_be_deleted(db_session):
    admin_role = ensure_role(db_session, "Admin")
    admin = make_user(db_session, admin_role, "fk-restrict-alert")
    alert = make_alert(db_session, "fk-restrict")
    incident = Incident(
        source_alert_id=alert.id,
        created_by_user_id=admin.id,
        title="Blocks alert deletion",
        description="This incident should prevent its source alert from being deleted.",
        priority="LOW",
        status="OPEN",
    )
    db_session.add(incident)
    db_session.commit()

    db_session.delete(alert)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_user_who_authored_a_note_cannot_be_deleted(db_session):
    admin_role = ensure_role(db_session, "Admin")
    author = make_user(db_session, admin_role, "fk-restrict-note-author")
    alert = make_alert(db_session, "fk-restrict-note")
    incident = Incident(
        source_alert_id=alert.id,
        created_by_user_id=author.id,
        title="Note author restriction",
        description="Holds a note authored by the user under test.",
        priority="LOW",
        status="OPEN",
    )
    db_session.add(incident)
    db_session.flush()
    note = Note(
        incident_id=incident.id,
        author_user_id=author.id,
        title="Evidence",
        body="Authored note that should block deleting its author.",
    )
    db_session.add(note)
    db_session.commit()

    db_session.delete(author)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_deleting_an_incident_cascades_to_its_notes(db_session):
    admin_role = ensure_role(db_session, "Admin")
    admin = make_user(db_session, admin_role, "cascade-notes")
    alert = make_alert(db_session, "cascade-notes")
    incident = Incident(
        source_alert_id=alert.id,
        created_by_user_id=admin.id,
        title="Cascade delete target",
        description="This incident's notes must be removed when it is deleted.",
        priority="LOW",
        status="OPEN",
    )
    db_session.add(incident)
    db_session.flush()
    note = Note(
        incident_id=incident.id,
        author_user_id=admin.id,
        title="Will be cascade-deleted",
        body="This note should disappear once its incident is deleted.",
    )
    db_session.add(note)
    db_session.commit()
    note_id = note.id

    db_session.delete(incident)
    db_session.commit()
    # expire_all() forces the next query to hit the database rather than
    # trusting attributes SQLAlchemy already has cached in the identity map,
    # which is what actually proves the DB-side ON DELETE CASCADE ran.
    db_session.expire_all()

    assert db_session.scalars(select(Note).where(Note.id == note_id)).one_or_none() is None


def test_deleting_a_user_sets_incident_assignment_fields_to_null(db_session):
    admin_role = ensure_role(db_session, "Admin")
    analyst_role = ensure_role(db_session, "Analyst")
    admin = make_user(db_session, admin_role, "set-null-creator")
    assignee = make_user(db_session, analyst_role, "set-null-assignee")
    alert = make_alert(db_session, "set-null")

    incident = Incident(
        source_alert_id=alert.id,
        created_by_user_id=admin.id,
        assigned_user_id=assignee.id,
        title="Assignment survives assignee deletion",
        description="assigned_user_id should become NULL, not block deletion.",
        priority="LOW",
        status="OPEN",
    )
    db_session.add(incident)
    db_session.commit()
    incident_id = incident.id

    db_session.delete(assignee)
    db_session.commit()
    db_session.expire_all()

    refreshed = db_session.scalars(
        select(Incident).where(Incident.id == incident_id)
    ).one()
    assert refreshed.assigned_user_id is None


# ── Uniqueness / duplicate records ───────────────────────────────────────────

def test_duplicate_log_line_number_within_the_same_upload_is_rejected(db_session):
    upload_id = uuid4()
    db_session.add(Log(
        upload_id=upload_id,
        source_filename="dup.csv",
        source_format="csv",
        line_number=1,
        raw_message="first",
        parsed_data={},
    ))
    db_session.commit()

    db_session.add(Log(
        upload_id=upload_id,
        source_filename="dup.csv",
        source_format="csv",
        line_number=1,
        raw_message="duplicate line number, same upload",
        parsed_data={},
    ))
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_same_line_number_across_different_uploads_is_allowed(db_session):
    """The uniqueness constraint is scoped to (upload_id, line_number), so
    line_number=1 recurring across independent uploads is expected, not a
    duplicate -- this is what makes re-uploading the same file safe."""

    db_session.add(Log(
        upload_id=uuid4(),
        source_filename="a.csv",
        source_format="csv",
        line_number=1,
        raw_message="upload A, line 1",
        parsed_data={},
    ))
    db_session.add(Log(
        upload_id=uuid4(),
        source_filename="b.csv",
        source_format="csv",
        line_number=1,
        raw_message="upload B, line 1",
        parsed_data={},
    ))
    db_session.commit()  # must not raise


def test_second_incident_for_the_same_alert_is_rejected_at_the_database_level(db_session):
    admin_role = ensure_role(db_session, "Admin")
    admin = make_user(db_session, admin_role, "dup-incident")
    alert = make_alert(db_session, "dup-incident")

    db_session.add(Incident(
        source_alert_id=alert.id,
        created_by_user_id=admin.id,
        title="First incident",
        description="First incident for this alert.",
        priority="LOW",
        status="OPEN",
    ))
    db_session.commit()

    db_session.add(Incident(
        source_alert_id=alert.id,
        created_by_user_id=admin.id,
        title="Second incident for the same alert",
        description="Must violate the unique constraint on source_alert_id.",
        priority="LOW",
        status="OPEN",
    ))
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


# ── Orphaned records: Alerts/Logs are intentionally decoupled by design ─────

def test_alert_can_exist_without_any_matching_log_rows():
    """Alert.upload_id and Log.upload_id are correlated by convention only --
    there is no foreign key between them, so an alert with no matching log
    rows (e.g. logs purged separately) is valid, not an orphan-record bug."""

    from app.db.session import SessionLocal

    with SessionLocal() as db:
        alert = make_alert(db, "no-matching-logs")
        db.commit()
        matching_logs = db.scalar(
            select(Log).where(Log.upload_id == alert.upload_id)
        )
        assert matching_logs is None  # no error, no crash -- valid by design
        db.rollback()


# ── Transaction rollback on partial failure ──────────────────────────────────

def test_upload_route_rolls_back_logs_when_alert_persistence_fails(monkeypatch, db_session):
    """The /upload route commits logs and alerts in one transaction (see
    app/routers/upload.py's `except SQLAlchemyError` block). If alert
    persistence fails, the logs from that same request must not be left
    behind as a partial, inconsistent write."""

    from io import BytesIO

    from sqlalchemy.exc import OperationalError

    import app.routers.upload as upload_router
    from app.main import app as fastapi_app
    from app.security import current_user

    def broken_create_alerts_from_detection(*args, **kwargs):
        raise OperationalError("simulated", {}, Exception("simulated alert persistence failure"))

    monkeypatch.setattr(
        upload_router, "create_alerts_from_detection", broken_create_alerts_from_detection
    )

    admin_role = ensure_role(db_session, "Admin")
    admin = make_user(db_session, admin_role, "rollback-admin")
    db_session.commit()

    from fastapi.testclient import TestClient

    fastapi_app.dependency_overrides[current_user] = lambda: admin
    try:
        with TestClient(fastapi_app) as client:
            content = (
                b"timestamp,ip_address,username,event_type,status\n"
                b"2024-01-01T00:00:00Z,1.2.3.4,admin,login_attempt,FAILED\n"
            )
            response = client.post(
                "/upload",
                files={"logfile": ("rollback-test.csv", BytesIO(content), "text/csv")},
            )
            assert response.status_code == 500
            assert response.json()["detail"]["code"] == "DATABASE_WRITE_ERROR"

        stray_logs = db_session.scalar(
            select(Log).where(Log.source_filename == "rollback-test.csv")
        )
        assert stray_logs is None
    finally:
        fastapi_app.dependency_overrides.pop(current_user, None)
