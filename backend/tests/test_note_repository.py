from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from app.repositories.note_repository import (
    NoteLimitReachedError,
    create_note_record,
    delete_note_record,
)


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


def test_delete_note_removes_existing_record():
    db = MagicMock()
    note = SimpleNamespace(id=12)
    db.get.return_value = note

    delete_note_record(db, note_id=12)

    db.delete.assert_called_once_with(note)
    db.flush.assert_called_once()
