from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.incident import Incident
from app.models.note import Note
from app.models.user import User
from app.repositories.incident_repository import (
    IncidentNotFoundError,
    UserNotFoundError,
)


MAX_NOTES_PER_INCIDENT = 5


class NoteLimitReachedError(Exception):
    """Raised when an incident already has the configured note limit."""


def create_note_record(
    db: Session,
    *,
    incident_id: int,
    author_user_id: int,
    title: str,
    body: str,
    tags: list[str] | None = None,
) -> Note:
    """Create a persistent analyst note."""

    # Lock the parent row so concurrent requests cannot both pass the limit
    # check and create a sixth note for the same incident.
    incident = db.scalar(
        select(Incident)
        .where(Incident.id == incident_id)
        .with_for_update()
    )

    if incident is None:
        raise IncidentNotFoundError(
            f"Incident {incident_id} does not exist."
        )

    note_count = db.scalar(
        select(func.count())
        .select_from(Note)
        .where(Note.incident_id == incident_id)
    ) or 0
    if note_count >= MAX_NOTES_PER_INCIDENT:
        raise NoteLimitReachedError(
            f"Incident {incident_id} already has the maximum of {MAX_NOTES_PER_INCIDENT} analyst notes."
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
        title=title.strip(),
        body=body.strip(),
        tags=tags or [],
    )

    db.add(note)
    db.flush()

    return note


def update_note_record(
    db: Session,
    *,
    note_id: int,
    updates: dict,
) -> Note:
    """Update the editable presentation fields of an incident note."""

    note = db.get(Note, note_id)
    if note is None:
        raise LookupError(f"Note {note_id} does not exist.")

    for field in ("title", "body", "tags", "pinned", "archived"):
        if field in updates and updates[field] is not None:
            setattr(note, field, updates[field])
    db.flush()
    return note


def delete_note_record(db: Session, *, note_id: int) -> None:
    """Permanently remove one analyst note."""

    note = db.get(Note, note_id)
    if note is None:
        raise LookupError(f"Note {note_id} does not exist.")
    db.delete(note)
    db.flush()


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


def list_all_note_records(
    db: Session,
    *,
    limit: int = 500,
) -> list[Note]:
    """Return workspace notes in one bounded query for list and search views."""

    statement = (
        select(Note)
        .order_by(
            Note.updated_at.desc(),
            Note.id.desc(),
        )
        .limit(limit)
    )
    return list(db.scalars(statement).all())


def serialize_note_record(note: Note) -> dict:
    """Convert a note into JSON-safe API data."""

    return {
        "id": note.id,
        "incident_id": note.incident_id,
        "author_user_id": note.author_user_id,
        "title": note.title,
        "body": note.body,
        "tags": note.tags,
        "pinned": note.pinned,
        "archived": note.archived,
        "created_at": note.created_at.isoformat(),
        "updated_at": note.updated_at.isoformat(),
    }
