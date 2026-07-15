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
    create_note_record,
    list_note_records,
    serialize_note_record,
)
from app.schemas.note import NoteCreate
from app.security import require_roles


router = APIRouter(tags=["Notes"])


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
            body=payload.body,
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
