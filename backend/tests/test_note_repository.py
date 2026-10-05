from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from app.repositories.note_repository import (
    NoteLimitReachedError,
    create_note_record,
    delete_note_record,
)


pytestmark = pytest.mark.no_db


def test_create_note_rejects_sixth_incident_note():
    db = MagicMock()
    db.scalar.side_effect = [SimpleNamespace(id=9), 5]

    with pytest.raises(NoteLimitReachedError, match="maximum of 5"):
        create_note_record(
            db,
            incident_id=9,
            author_user_id=3,
            title="Investigation update",
            body="Validated the affected host.",
        )

    db.add.assert_not_called()


@pytest.mark.db
def test_delete_note_removes_record_but_retains_audit_snapshot(db_session):
    from uuid import uuid4
    from sqlalchemy import select
    from app.models.alert import Alert
    from app.models.note import Note
    from app.models.role import Role
    from app.models.user import User
    from app.models.workflow import WorkflowEvent
    from app.repositories.incident_repository import create_incident_from_alert

    suffix = uuid4().hex
    role = db_session.scalar(select(Role).where(Role.name == "Analyst"))
    user = User(role_id=role.id, username=suffix, email=f"{suffix}@example.test", password_hash="unused")
    alert = Alert(upload_id=uuid4(), rule="test", title="Test", description="Source", severity="HIGH")
    db_session.add_all([user, alert])
    db_session.flush()
    incident = create_incident_from_alert(db_session, alert_id=alert.id, created_by_user_id=user.id)
    note = create_note_record(db_session, incident_id=incident.id, author_user_id=user.id, title="Review", body="Validated the affected host.")
    note_id = note.id
    delete_note_record(db_session, note_id=note_id, actor_user_id=user.id)
    assert db_session.get(Note, note_id) is None
    audit = db_session.scalar(select(WorkflowEvent).where(WorkflowEvent.incident_id == incident.id, WorkflowEvent.event_type == "NOTE_DELETED"))
    assert audit.before["body"] == "Validated the affected host."
    assert audit.actor_user_id == user.id
