from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    status,
)
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.user import User
from app.repositories.incident_repository import (
    IncidentNotFoundError,
    UserNotFoundError,
)
from app.repositories.note_repository import (
    NoteLimitReachedError,
    create_note_record,
    delete_note_record,
    list_all_note_records,
    list_note_records,
    serialize_note_record,
    update_note_record,
)
from app.schemas.note import NoteCreate, NoteUpdate
from app.security import require_roles


router = APIRouter(tags=["Notes"])


@router.get("/notes")
def get_workspace_notes(
    limit: int = Query(default=500, ge=1, le=500),
    user: User = Depends(require_roles("Admin", "Analyst", "Viewer")),
    db: Session = Depends(get_db),
):
    """Return analyst notes without one request per incident."""

    notes = list_all_note_records(db, limit=limit)
    return {
        "success": True,
        "count": len(notes),
        "notes": [serialize_note_record(note) for note in notes],
    }


@router.post(
    "/incidents/{incident_id}/notes",
    status_code=status.HTTP_201_CREATED,
)
def create_incident_note(
    incident_id: int,
    payload: NoteCreate,
    user: User = Depends(require_roles("Admin", "Analyst")),
    db: Session = Depends(get_db),
):
    """Add an analyst note to an incident."""

    try:
        note = create_note_record(
            db,
            incident_id=incident_id,
            author_user_id=user.id,
            title=payload.title,
            body=payload.body,
            tags=payload.tags,
        )

        db.commit()
        db.refresh(note)

    except IncidentNotFoundError as exc:
        db.rollback()

        raise HTTPException(
            status_code=404,
            detail=str(exc),
        ) from exc

    except UserNotFoundError as exc:
        db.rollback()

        raise HTTPException(
            status_code=404,
            detail=str(exc),
        ) from exc

    except NoteLimitReachedError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc

    except SQLAlchemyError as exc:
        db.rollback()

        raise HTTPException(
            status_code=500,
            detail="Analyst note could not be saved.",
        ) from exc

    return {
        "success": True,
        "note": serialize_note_record(note),
    }


@router.patch("/notes/{note_id}")
def update_incident_note(
    note_id: int,
    payload: NoteUpdate,
    user: User = Depends(require_roles("Admin", "Analyst")),
    db: Session = Depends(get_db),
):
    """Update note content and analyst-managed presentation fields."""

    try:
        note = update_note_record(
            db,
            note_id=note_id,
            updates=payload.model_dump(exclude_unset=True),
        )
        db.commit()
        db.refresh(note)
    except LookupError as exc:
        db.rollback()
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail="Analyst note could not be updated.") from exc

    return {"success": True, "note": serialize_note_record(note)}


@router.delete("/notes/{note_id}")
def delete_incident_note(
    note_id: int,
    user: User = Depends(require_roles("Admin", "Analyst")),
    db: Session = Depends(get_db),
):
    """Permanently delete one analyst note."""

    try:
        delete_note_record(db, note_id=note_id)
        db.commit()
    except LookupError as exc:
        db.rollback()
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail="Analyst note could not be deleted.") from exc
    return {"success": True, "deleted_note_id": note_id}


@router.get("/incidents/{incident_id}/notes")
def get_incident_notes(
    incident_id: int,
    limit: int = Query(
        default=100,
        ge=1,
        le=500,
    ),
    user: User = Depends(require_roles("Admin", "Analyst", "Viewer")),
    db: Session = Depends(get_db),
):
    """Return an incident's analyst notes."""

    try:
        notes = list_note_records(
            db,
            incident_id=incident_id,
            limit=limit,
        )

    except IncidentNotFoundError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        ) from exc

    serialized_notes = [
        serialize_note_record(note)
        for note in notes
    ]

    return {
        "success": True,
        "incident_id": incident_id,
        "count": len(serialized_notes),
        "notes": serialized_notes,
    }
