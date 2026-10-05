from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.incident import Incident
from app.models.user import User
from app.models.workflow import IncidentAlertLink
from app.services.incident_workflow import eligible_assignee, update_incident
from app.services.workflow import locked, record_event, transition_alert


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
    created_by_user_id: int | None = None,
    assigned_user_id: int | None = None,
    title: str | None = None,
    description: str | None = None,
    priority: str | None = None,
) -> Incident:
    """Create one incident from a persistent alert."""

    alert = locked(db, Alert, alert_id)

    existing_incident = db.scalar(
        select(Incident).where(
            Incident.id.in_(
                select(IncidentAlertLink.incident_id).where(
                    IncidentAlertLink.alert_id == alert_id
                )
            )
        )
    )

    if existing_incident is not None:
        raise IncidentAlreadyExistsError(f"Alert {alert_id} already has an incident.")

    eligible_assignee(db, assigned_user_id)

    if created_by_user_id is not None:
        creator = db.get(User, created_by_user_id)

        if creator is None:
            raise UserNotFoundError(f"User {created_by_user_id} does not exist.")

    incident = Incident(
        source_alert_id=alert.id,
        assigned_user_id=assigned_user_id,
        created_by_user_id=created_by_user_id,
        updated_by_user_id=created_by_user_id,
        title=title or alert.title,
        description=description or alert.description,
        priority=(priority or alert.severity).upper(),
        status="OPEN",
        response_playbook=dict(alert.response_playbook or {}),
    )

    # Escalating an alert into an incident updates the alert lifecycle.
    if alert.investigation_state != "ESCALATED":
        transition_alert(db, alert, "ESCALATED", actor_id=created_by_user_id)

    db.add(incident)
    db.flush()

    db.add(IncidentAlertLink(incident_id=incident.id, alert_id=alert.id))
    record_event(
        db,
        actor_id=created_by_user_id,
        incident_id=incident.id,
        event_type="CREATED",
        after={
            "status": incident.status,
            "source_alert_id": alert.id,
            "assigned_user_id": assigned_user_id,
            "version": incident.version,
        },
    )
    return incident


def get_incident_record(
    db: Session,
    incident_id: int,
) -> Incident:
    """Return one incident or raise an exception."""

    incident = db.get(Incident, incident_id)

    if incident is None:
        raise IncidentNotFoundError(f"Incident {incident_id} does not exist.")

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
        statement = statement.where(Incident.status == status.upper())

    if priority:
        statement = statement.where(Incident.priority == priority.upper())

    if assigned_user_id is not None:
        statement = statement.where(Incident.assigned_user_id == assigned_user_id)

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
    updated_by_user_id: int | None = None,
) -> Incident:
    """Apply guarded, audited updates through the common lifecycle service."""
    return update_incident(db, incident_id, updates, updated_by_user_id)


def serialize_incident_record(
    incident: Incident,
) -> dict:
    """Convert an Incident model into JSON-safe data."""

    return {
        "id": incident.id,
        "version": incident.version,
        "resolution_reason": incident.resolution_reason,
        "resolution_note": incident.resolution_note,
        "resolved_by_user_id": incident.resolved_by_user_id,
        "resolved_by_name": incident.resolved_by_name,
        "source_alert_id": incident.source_alert_id,
        "linked_alert_ids": [link.alert_id for link in incident.alert_links],
        "assigned_user_id": incident.assigned_user_id,
        "created_by_user_id": incident.created_by_user_id,
        "updated_by_user_id": incident.updated_by_user_id,
        "title": incident.title,
        "description": incident.description,
        "priority": incident.priority,
        "status": incident.status,
        "opened_at": incident.opened_at.isoformat(),
        "resolved_at": (
            incident.resolved_at.isoformat() if incident.resolved_at else None
        ),
        "closed_at": (incident.closed_at.isoformat() if incident.closed_at else None),
        "response_playbook": incident.response_playbook,
        "playbook": incident.response_playbook,
        "created_at": incident.created_at.isoformat(),
        "updated_at": incident.updated_at.isoformat(),
    }
