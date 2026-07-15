from fastapi import APIRouter, Depends, HTTPException

from app.models.user import User
from app.security import require_roles
from fastapi import Query
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.repositories.alert_repository import (
    AlertNotFoundError,
    list_alert_records,
    serialize_alert_record,
    update_alert_record,
)
from app.schemas.alert import AlertUpdate


router = APIRouter(tags=["Alerts"])


@router.get("/alerts")
def get_alerts(
    severity: str | None = Query(
        default=None,
        description="Optional severity filter.",
    ),
    status: str | None = Query(
        default=None,
        description="Optional alert status filter.",
    ),
    limit: int = Query(
        default=100,
        ge=1,
        le=500,
    ),
    user: User = Depends(require_roles("Admin", "Analyst", "Viewer")),
    db: Session = Depends(get_db),
):
    """Return persistent alerts from PostgreSQL."""

    records = list_alert_records(
        db,
        severity=severity,
        status=status,
        limit=limit,
    )

    alerts = [
        serialize_alert_record(record)
        for record in records
    ]

    return {
        "success": True,
        "count": len(alerts),
        "alerts": alerts,
    }


@router.patch("/alerts/{alert_id}")
def update_alert(
    alert_id: int,
    payload: AlertUpdate,
    user: User = Depends(require_roles("Admin", "Analyst")),
    db: Session = Depends(get_db),
):
    """Update an alert's workflow status or severity."""

    updates = payload.model_dump(
        exclude_unset=True,
    )

    try:
        alert = update_alert_record(
            db,
            alert_id=alert_id,
            severity=updates.get("severity"),
            status=updates.get("status"),
        )

        db.commit()
        db.refresh(alert)

    except AlertNotFoundError as exc:
        db.rollback()

        raise HTTPException(
            status_code=404,
            detail=str(exc),
        ) from exc

    except SQLAlchemyError as exc:
        db.rollback()

        raise HTTPException(
            status_code=500,
            detail="Alert could not be updated.",
        ) from exc

    return {
        "success": True,
        "alert": serialize_alert_record(alert),
    }
