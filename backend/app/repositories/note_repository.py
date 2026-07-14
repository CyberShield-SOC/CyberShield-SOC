from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.incident import Incident
from app.models.note import Note
from app.models.user import User
from app.repositories.incident_repository import (
    IncidentNotFoundError,
    UserNotFoundError,
)


def create_note_record(
    db: Session,
    *,
    incident_id: int,
    author_user_id: int,
    body: str,
) -> Note:
    """Create a persistent analyst note."""

    incident = db.get(
        Incident,
        incident_id,
    )

    if incident is None:
        raise IncidentNotFoundError(
            f"Incident {incident_id} does not exist."
        )

    author = db.get(
        User,
        author_user_id,
    )

    if author is None:
        raise UserNotFoundError(
            f"User {author_user_id} does not exist."
        )

    note = Note(
        incident_id=incident_id,
        author_user_id=author_user_id,
        body=body.strip(),
    )

    db.add(note)
    db.flush()

    return note


def list_note_records(
    db: Session,
    *,
    incident_id: int,
    limit: int = 100,
) -> list[Note]:
    """Return an incident's notes in chronological order."""

    incident = db.get(
        Incident,
        incident_id,
    )

    if incident is None:
        raise IncidentNotFoundError(
            f"Incident {incident_id} does not exist."
        )

    statement = (
        select(Note)
        .where(Note.incident_id == incident_id)
        .order_by(
            Note.created_at.asc(),
            Note.id.asc(),
        )
        .limit(limit)
    )

    return list(
        db.scalars(statement).all()
    )


def serialize_note_record(note: Note) -> dict:
    """Convert a note into JSON-safe API data."""

    return {
        "id": note.id,
        "incident_id": note.incident_id,
        "author_user_id": note.author_user_id,
        "body": note.body,
        "created_at": note.created_at.isoformat(),
        "updated_at": note.updated_at.isoformat(),
    }