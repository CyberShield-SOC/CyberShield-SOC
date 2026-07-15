from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    status,
)
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.user import User
from app.repositories.incident_repository import (
    AlertNotFoundError,
    IncidentAlreadyExistsError,
    IncidentNotFoundError,
    UserNotFoundError,
    create_incident_from_alert,
    get_incident_record,
    list_incident_records,
    serialize_incident_record,
    update_incident_record,
)
from app.schemas.incident import (
    IncidentCreate,
    IncidentUpdate,
)
from app.security import require_roles


router = APIRouter(tags=["Incidents"])


@router.post(
    "/incidents",
    status_code=status.HTTP_201_CREATED,
)
def create_incident(
    payload: IncidentCreate,
    user: User = Depends(require_roles("Admin", "Analyst")),
    db: Session = Depends(get_db),
):
    """Create an incident from an existing persistent alert."""

    try:
        incident = create_incident_from_alert(
            db,
            alert_id=payload.alert_id,
            created_by_user_id=user.id,
            assigned_user_id=payload.assigned_user_id,
            title=payload.title,
            description=payload.description,
            priority=payload.priority,
        )

        db.commit()
        db.refresh(incident)

    except AlertNotFoundError as exc:
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

    except IncidentAlreadyExistsError as exc:
        db.rollback()

        raise HTTPException(
            status_code=409,
            detail=str(exc),
        ) from exc

    except IntegrityError as exc:
        db.rollback()

        raise HTTPException(
            status_code=409,
            detail="An incident already exists for this alert.",
        ) from exc

    except SQLAlchemyError as exc:
        db.rollback()

        raise HTTPException(
            status_code=500,
            detail="Incident could not be created.",
        ) from exc

    return {
        "success": True,
        "incident": serialize_incident_record(incident),
    }


@router.get("/incidents")
def get_incidents(
    incident_status: str | None = Query(
        default=None,
        alias="status",
    ),
    priority: str | None = Query(default=None),
    assigned_user_id: int | None = Query(
        default=None,
        gt=0,
    ),
    limit: int = Query(
        default=100,
        ge=1,
        le=500,
    ),
    user: User = Depends(require_roles("Admin", "Analyst", "Viewer")),
    db: Session = Depends(get_db),
):
    """Return persistent incidents with optional filters."""

    incidents = list_incident_records(
        db,
        status=incident_status,
        priority=priority,
        assigned_user_id=assigned_user_id,
        limit=limit,
    )

    serialized = [
        serialize_incident_record(incident)
        for incident in incidents
    ]

    return {
        "success": True,
        "count": len(serialized),
        "incidents": serialized,
    }


@router.get("/incidents/{incident_id}")
def get_incident(
    incident_id: int,
    user: User = Depends(require_roles("Admin", "Analyst", "Viewer")),
    db: Session = Depends(get_db),
):
    """Return one persistent incident."""

    try:
        incident = get_incident_record(
            db,
            incident_id,
        )

    except IncidentNotFoundError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        ) from exc

    return {
        "success": True,
        "incident": serialize_incident_record(incident),
    }


@router.patch("/incidents/{incident_id}")
def update_incident(
    incident_id: int,
    payload: IncidentUpdate,
    user: User = Depends(require_roles("Admin", "Analyst")),
    db: Session = Depends(get_db),
):
    """Update assignment, status, priority, or incident details."""

    updates = payload.model_dump(
        exclude_unset=True,
    )

    try:
        incident = update_incident_record(
            db,
            incident_id=incident_id,
            updates=updates,
            updated_by_user_id=user.id,
        )

        db.commit()
        db.refresh(incident)

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
            detail="Incident could not be updated.",
        ) from exc

    return {
        "success": True,
        "incident": serialize_incident_record(incident),
    }
