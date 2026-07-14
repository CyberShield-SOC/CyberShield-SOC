from fastapi import APIRouter, Depends

from app.models.user import User
from app.security import require_roles
from fastapi import Query
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.repositories.alert_repository import (
    list_alert_records,
    serialize_alert_record,
)


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
