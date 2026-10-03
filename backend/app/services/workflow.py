"""Shared row locks, actor attribution, and investigation transitions."""

from functools import wraps

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from app.models.incident import Incident
from app.models.user import User
from app.models.workflow import IncidentAlertLink, WorkflowEvent

PROJECTION = {
    "NEW": "NEW",
    "INVESTIGATING": "REVIEWING",
    "ESCALATED": "ESCALATED",
    "RESOLVED": "CLOSED",
    "FALSE_POSITIVE": "CLOSED",
    "LEGACY_CLOSED": "CLOSED",
}
ALERT_TRANSITIONS = {
    "NEW": {"INVESTIGATING", "ESCALATED", "RESOLVED", "FALSE_POSITIVE"},
    "INVESTIGATING": {"ESCALATED", "RESOLVED", "FALSE_POSITIVE"},
    "ESCALATED": {"INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"},
    "RESOLVED": {"INVESTIGATING"},
    "FALSE_POSITIVE": {"INVESTIGATING"},
    "LEGACY_CLOSED": {"INVESTIGATING"},
}


def locked(db, model, identity):
    # Preserve pending action/playbook changes before refreshing a locked row.
    db.flush()
    record = db.scalar(
        select(model)
        .where(model.id == identity)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if record is None:
        raise HTTPException(404, f"{model.__name__} {identity} does not exist.")
    return record


def check_version(record, expected):
    if expected is not None and record.version != expected:
        raise HTTPException(409, "This record changed. Reload it before trying again.")


def record_event(
    db,
    *,
    actor_id=None,
    alert_id=None,
    incident_id=None,
    event_type,
    before=None,
    after=None,
    reason=None,
    note=None,
):
    actor = db.get(User, actor_id) if actor_id else None
    if actor_id and actor is None:
        raise HTTPException(404, "The responsible user does not exist.")
    event = WorkflowEvent(
        actor_user_id=actor_id,
        actor_name=(actor.full_name or actor.username) if actor else "System",
        alert_id=alert_id,
        incident_id=incident_id,
        event_type=event_type,
        before=before or {},
        after=after or {},
        reason=reason,
        note=note,
    )
    db.add(event)
    db.flush()
    return event


def transition_alert(
    db,
    alert,
    state,
    *,
    actor_id=None,
    reason=None,
    expected_version=None,
    incident_owned=False,
):
    check_version(alert, expected_version)
    old = alert.investigation_state
    if state == old:
        raise HTTPException(409, f"Alert is already {state}.")
    if state not in ALERT_TRANSITIONS[old]:
        raise HTTPException(409, f"Cannot transition an alert from {old} to {state}.")
    if not incident_owned:
        linked = db.scalar(
            select(Incident.id)
            .join(IncidentAlertLink, IncidentAlertLink.incident_id == Incident.id)
            .where(
                IncidentAlertLink.alert_id == alert.id,
                Incident.status.in_(["OPEN", "INVESTIGATING"]),
            )
        )
        if linked:
            raise HTTPException(409, "Update the active incident that owns this alert.")
    alert.investigation_state = state
    alert.status = PROJECTION[state]
    alert.version += 1
    record_event(
        db,
        actor_id=actor_id,
        alert_id=alert.id,
        event_type="STATE_CHANGED",
        before={"state": old},
        after={"state": state, "version": alert.version},
        reason=reason,
    )
    return alert


def commit_workflow(db):
    try:
        db.commit()
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(500, "The workflow change could not be saved.") from exc


def workflow_transaction(function):
    """Roll back failures during validation, flush, or commit of new endpoints."""

    @wraps(function)
    def wrapped(*args, **kwargs):
        db = kwargs["db"]
        try:
            return function(*args, **kwargs)
        except HTTPException:
            db.rollback()
            raise
        except SQLAlchemyError as exc:
            db.rollback()
            raise HTTPException(500, "The workflow change could not be saved.") from exc

    return wrapped


def serialize_event(event):
    return {
        "id": event.id,
        "alert_id": event.alert_id,
        "incident_id": event.incident_id,
        "actor_user_id": event.actor_user_id,
        "actor_name": event.actor_name,
        "event_type": event.event_type,
        "occurred_at": event.occurred_at.isoformat(),
        "before": event.before,
        "after": event.after,
        "reason": event.reason,
        "note": event.note,
    }


def history_page(db, event_filter, *, after_id, limit):
    """Return an entity's history in ID order with an exclusive cursor."""
    rows = list(
        db.scalars(
            select(WorkflowEvent)
            .where(event_filter, WorkflowEvent.id > after_id)
            .order_by(WorkflowEvent.id)
            .limit(limit + 1)
        )
    )
    visible = rows[:limit]
    return {
        "success": True,
        "events": [serialize_event(event) for event in visible],
        "next_after_id": visible[-1].id if len(rows) > limit else None,
    }
