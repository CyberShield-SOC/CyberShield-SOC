"""Atomic incident lifecycle operations shared by every write endpoint."""

from datetime import datetime, timezone

from fastapi import HTTPException
from sqlalchemy import select

from app.models.alert import Alert
from app.models.incident import Incident
from app.models.user import User
from app.models.workflow import IncidentAlertLink
from app.services.workflow import check_version, locked, record_event, transition_alert

ACTIVE = {"OPEN", "INVESTIGATING"}
TERMINAL = {"RESOLVED", "FALSE_POSITIVE"}


def eligible_assignee(db, identity):
    if identity is None:
        return
    user = db.get(User, identity)
    if user is None:
        raise HTTPException(404, f"User {identity} does not exist.")
    if not user.is_active or user.role.name not in {"Admin", "Analyst"}:
        raise HTTPException(422, "Assign incidents to an active Admin or Analyst.")


def snapshot(incident):
    return {
        field: getattr(incident, field)
        for field in (
            "status",
            "assigned_user_id",
            "priority",
            "title",
            "description",
            "resolution_reason",
            "resolution_note",
            "resolved_by_user_id",
            "resolved_by_name",
            "version",
        )
    }


def linked_alerts(db, incident):
    return list(
        db.scalars(
            select(Alert)
            .join(IncidentAlertLink, IncidentAlertLink.alert_id == Alert.id)
            .where(IncidentAlertLink.incident_id == incident.id)
            .order_by(Alert.id)
            .with_for_update(of=Alert)
            .execution_options(populate_existing=True)
        )
    )


def update_incident(db, identity, updates, actor_id):
    incident = locked(db, Incident, identity)
    check_version(incident, updates.get("expected_version"))
    before = snapshot(incident)
    target = updates.get("status")
    reason, note = (
        updates.get("resolution_reason") or updates.get("reason"),
        updates.get("resolution_note"),
    )
    kind = "UPDATED"
    if target is not None and target != incident.status:
        if incident.status in ACTIVE and target in TERMINAL:
            if not reason or not reason.strip() or not note or not note.strip():
                raise HTTPException(
                    422, "Resolving an incident requires a resolution reason and note."
                )
            kind = "RESOLVED"
            now = datetime.now(timezone.utc)
            incident.resolution_reason, incident.resolution_note = (
                reason.strip(),
                note.strip(),
            )
            actor = db.get(User, actor_id) if actor_id else None
            incident.resolved_by_user_id = actor_id
            incident.resolved_by_name = (
                (actor.full_name or actor.username) if actor else "System"
            )
            incident.resolved_at = now
            incident.closed_at = now if target == "FALSE_POSITIVE" else None
        elif incident.status in TERMINAL and target in ACTIVE:
            if not updates.get("reason") or not updates["reason"].strip():
                raise HTTPException(422, "Reopening an incident requires a reason.")
            kind = "REOPENED"
            incident.resolved_at = incident.closed_at = None
            incident.resolution_reason = incident.resolution_note = None
            incident.resolved_by_user_id = incident.resolved_by_name = None
        elif incident.status == "OPEN" and target == "INVESTIGATING":
            kind = "STATUS_CHANGED"
        else:
            raise HTTPException(
                409,
                f"Cannot transition an incident from {incident.status} to {target}.",
            )
        incident.status = target
        for alert in linked_alerts(db, incident):
            alert_target = target if target in TERMINAL else "INVESTIGATING"
            if alert.investigation_state != alert_target:
                transition_alert(
                    db,
                    alert,
                    alert_target,
                    actor_id=actor_id,
                    reason=reason,
                    incident_owned=True,
                )
    elif (
        target is not None
        and target == incident.status
        and set(updates)
        <= {
            "status",
            "expected_version",
            "reason",
            "resolution_reason",
            "resolution_note",
        }
    ):
        raise HTTPException(409, f"Incident is already {target}.")
    if "assigned_user_id" in updates:
        eligible_assignee(db, updates["assigned_user_id"])
    for field in ("assigned_user_id", "title", "description", "priority"):
        if field in updates and (
            updates[field] is not None or field == "assigned_user_id"
        ):
            setattr(incident, field, updates[field])
    if snapshot(incident) == before:
        return incident
    incident.version += 1
    incident.updated_by_user_id = actor_id
    after = snapshot(incident)
    after.update(
        resolved_at=incident.resolved_at.isoformat() if incident.resolved_at else None,
        closed_at=incident.closed_at.isoformat() if incident.closed_at else None,
    )
    record_event(
        db,
        actor_id=actor_id,
        incident_id=incident.id,
        event_type=kind,
        before=before,
        after=after,
        reason=reason,
        note=note if kind == "RESOLVED" else None,
    )
    return incident


def link_alert(
    db, incident_id, alert_id, actor_id, expected_version=None, remove=False
):
    incident = locked(db, Incident, incident_id)
    check_version(incident, expected_version)
    if incident.status not in ACTIVE:
        raise HTTPException(
            409, "Reopen the incident before changing its linked alerts."
        )
    alert = locked(db, Alert, alert_id)
    existing = db.scalar(
        select(IncidentAlertLink).where(IncidentAlertLink.alert_id == alert_id)
    )
    if remove:
        if alert_id == incident.source_alert_id:
            raise HTTPException(409, "The primary source alert cannot be unlinked.")
        if existing is None or existing.incident_id != incident_id:
            raise HTTPException(404, "This alert is not linked to the incident.")
        db.delete(existing)
        if alert.investigation_state == "ESCALATED":
            transition_alert(
                db, alert, "INVESTIGATING", actor_id=actor_id, incident_owned=True
            )
    else:
        if existing:
            raise HTTPException(409, "This alert already belongs to an incident.")
        if alert.investigation_state in TERMINAL | {"LEGACY_CLOSED"}:
            raise HTTPException(
                409, "Reopen the alert investigation before linking it."
            )
        db.add(IncidentAlertLink(incident_id=incident_id, alert_id=alert_id))
        if alert.investigation_state != "ESCALATED":
            transition_alert(
                db, alert, "ESCALATED", actor_id=actor_id, incident_owned=True
            )
    incident.version += 1
    incident.updated_by_user_id = actor_id
    record_event(
        db,
        actor_id=actor_id,
        incident_id=incident_id,
        event_type="ALERT_UNLINKED" if remove else "ALERT_LINKED",
        after={"alert_id": alert_id, "version": incident.version},
    )
    db.expire(incident, ["alert_links"])
    return incident
