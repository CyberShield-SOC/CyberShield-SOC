from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.incident import Incident
from app.models.user import User


class AlertNotFoundError(Exception):
    """Raised when the requested alert does not exist."""


class UserNotFoundError(Exception):
    """Raised when the assigned user does not exist."""


class IncidentNotFoundError(Exception):
    """Raised when the requested incident does not exist."""


class IncidentAlreadyExistsError(Exception):
    """Raised when an alert already has an incident."""


def create_incident_from_alert(
    db: Session,
    *,
    alert_id: int,
    assigned_user_id: int | None = None,
    title: str | None = None,
    description: str | None = None,
    priority: str | None = None,
) -> Incident:
    """Create one incident from a persistent alert."""

    alert = db.get(Alert, alert_id)

    if alert is None:
        raise AlertNotFoundError(
            f"Alert {alert_id} does not exist."
        )

    existing_incident = db.scalar(
        select(Incident).where(
            Incident.source_alert_id == alert_id
        )
    )

    if existing_incident is not None:
        raise IncidentAlreadyExistsError(
            f"Alert {alert_id} already has an incident."
        )

    if assigned_user_id is not None:
        assigned_user = db.get(User, assigned_user_id)

        if assigned_user is None:
            raise UserNotFoundError(
                f"User {assigned_user_id} does not exist."
            )

    incident = Incident(
        source_alert_id=alert.id,
        assigned_user_id=assigned_user_id,
        title=title or alert.title,
        description=description or alert.description,
        priority=(priority or alert.severity).upper(),
        status="OPEN",
    )

    # Escalating an alert into an incident updates the alert lifecycle.
    alert.status = "ESCALATED"

    db.add(incident)
    db.flush()

    return incident


def get_incident_record(
    db: Session,
    incident_id: int,
) -> Incident:
    """Return one incident or raise an exception."""

    incident = db.get(Incident, incident_id)

    if incident is None:
        raise IncidentNotFoundError(
            f"Incident {incident_id} does not exist."
        )

    return incident


def list_incident_records(
    db: Session,
    *,
    status: str | None = None,
    priority: str | None = None,
    assigned_user_id: int | None = None,
    limit: int = 100,
) -> list[Incident]:
    """Return incidents with optional filters."""

    statement = select(Incident)

    if status:
        statement = statement.where(
            Incident.status == status.upper()
        )

    if priority:
        statement = statement.where(
            Incident.priority == priority.upper()
        )

    if assigned_user_id is not None:
        statement = statement.where(
            Incident.assigned_user_id == assigned_user_id
        )

    statement = statement.order_by(
        Incident.created_at.desc(),
        Incident.id.desc(),
    ).limit(limit)

    return list(db.scalars(statement).all())


def update_incident_record(
    db: Session,
    *,
    incident_id: int,
    updates: dict[str, Any],
) -> Incident:
    """Apply allowed incident updates."""

    incident = get_incident_record(
        db,
        incident_id,
    )

    if "assigned_user_id" in updates:
        assigned_user_id = updates["assigned_user_id"]

        if assigned_user_id is not None:
            user = db.get(User, assigned_user_id)

            if user is None:
                raise UserNotFoundError(
                    f"User {assigned_user_id} does not exist."
                )

        incident.assigned_user_id = assigned_user_id

    if "title" in updates and updates["title"] is not None:
        incident.title = updates["title"]

    if (
        "description" in updates
        and updates["description"] is not None
    ):
        incident.description = updates["description"]

    if "priority" in updates and updates["priority"] is not None:
        incident.priority = updates["priority"].upper()

    if "status" in updates and updates["status"] is not None:
        new_status = updates["status"].upper()
        now = datetime.now(timezone.utc)

        incident.status = new_status

        if new_status == "RESOLVED":
            incident.resolved_at = now
            incident.closed_at = None

        elif new_status == "CLOSED":
            if incident.resolved_at is None:
                incident.resolved_at = now

            incident.closed_at = now

        elif new_status in {"OPEN", "INVESTIGATING"}:
            incident.resolved_at = None
            incident.closed_at = None

    db.flush()

    return incident


def serialize_incident_record(
    incident: Incident,
) -> dict:
    """Convert an Incident model into JSON-safe data."""

    return {
        "id": incident.id,
        "source_alert_id": incident.source_alert_id,
        "assigned_user_id": incident.assigned_user_id,
        "title": incident.title,
        "description": incident.description,
        "priority": incident.priority,
        "status": incident.status,
        "opened_at": incident.opened_at.isoformat(),
        "resolved_at": (
            incident.resolved_at.isoformat()
            if incident.resolved_at
            else None
        ),
        "closed_at": (
            incident.closed_at.isoformat()
            if incident.closed_at
            else None
        ),
        "created_at": incident.created_at.isoformat(),
        "updated_at": incident.updated_at.isoformat(),
    }