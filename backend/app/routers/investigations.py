from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.alert import Alert
from app.models.incident import Incident
from app.models.user import User
from app.models.workflow import IncidentAlertLink, InvestigationNote, WorkflowEvent
from app.repositories.alert_repository import serialize_alert_record
from app.repositories.correlation_repository import paginate
from app.repositories.incident_repository import (
    IncidentAlreadyExistsError,
    create_incident_from_alert,
    serialize_incident_record,
)
from app.security import require_roles
from app.services.workflow import (
    ALERT_TRANSITIONS,
    check_version,
    commit_workflow,
    history_page,
    locked,
    record_event,
    transition_alert,
    workflow_transaction,
)

router = APIRouter(tags=["Investigations"])
read_role = require_roles("Admin", "Analyst", "Viewer")
write_role = require_roles("Admin", "Analyst")


class StateUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    state: Literal["NEW", "INVESTIGATING", "ESCALATED", "RESOLVED", "FALSE_POSITIVE"]
    expected_version: int | None = Field(None, gt=0)
    reason: str | None = Field(None, min_length=1, max_length=2000)


class AnalystNote(BaseModel):
    model_config = ConfigDict(extra="forbid")
    body: str = Field(min_length=1, max_length=5000)
    expected_version: int | None = Field(None, gt=0)

    @field_validator("body")
    @classmethod
    def nonblank(cls, value):
        if not value.strip():
            raise ValueError("An analyst note cannot be blank.")
        return value.strip()


def _serialize_note(note):
    return {
        "id": note.id,
        "body": note.body,
        "author_user_id": note.author_user_id,
        "created_at": note.created_at.isoformat(),
    }


@router.get("/alerts/{alert_id}/investigation")
def details(
    alert_id: int, user: User = Depends(read_role), db: Session = Depends(get_db)
):
    alert = locked(db, Alert, alert_id)
    owner = db.scalar(
        select(Incident.id)
        .join(IncidentAlertLink, IncidentAlertLink.incident_id == Incident.id)
        .where(
            IncidentAlertLink.alert_id == alert_id,
            Incident.status.in_(["OPEN", "INVESTIGATING"]),
        )
    )
    return {
        "success": True,
        "alert": serialize_alert_record(alert),
        "active_incident_id": owner,
        "allowed_states": []
        if owner
        else sorted(ALERT_TRANSITIONS[alert.investigation_state]),
    }


@router.patch("/alerts/{alert_id}/investigation")
@workflow_transaction
def change_state(
    alert_id: int,
    payload: StateUpdate,
    user: User = Depends(write_role),
    db: Session = Depends(get_db),
):
    alert = transition_alert(
        db,
        locked(db, Alert, alert_id),
        payload.state,
        actor_id=user.id,
        reason=payload.reason,
        expected_version=payload.expected_version,
    )
    commit_workflow(db)
    return {"success": True, "alert": serialize_alert_record(alert)}


@router.post("/alerts/{alert_id}/escalate", status_code=201)
@workflow_transaction
def escalate(
    alert_id: int, user: User = Depends(write_role), db: Session = Depends(get_db)
):
    try:
        incident = create_incident_from_alert(
            db, alert_id=alert_id, created_by_user_id=user.id
        )
    except IncidentAlreadyExistsError as exc:
        db.rollback()
        raise HTTPException(409, str(exc)) from exc
    commit_workflow(db)
    return {"success": True, "incident": serialize_incident_record(incident)}


@router.post("/alerts/{alert_id}/investigation/notes", status_code=201)
@workflow_transaction
def add_note(
    alert_id: int,
    payload: AnalystNote,
    user: User = Depends(write_role),
    db: Session = Depends(get_db),
):
    alert = locked(db, Alert, alert_id)
    check_version(alert, payload.expected_version)
    note = InvestigationNote(
        alert_id=alert.id, author_user_id=user.id, body=payload.body
    )
    db.add(note)
    db.flush()
    alert.version += 1
    record_event(
        db,
        alert_id=alert.id,
        actor_id=user.id,
        event_type="NOTE_ADDED",
        after={"note_id": note.id, "version": alert.version},
        note=note.body,
    )
    commit_workflow(db)
    return {"success": True, "note": _serialize_note(note), "version": alert.version}


@router.get("/alerts/{alert_id}/investigation/notes")
def notes(
    alert_id: int,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    user: User = Depends(read_role),
    db: Session = Depends(get_db),
):
    locked(db, Alert, alert_id)
    rows, pagination = paginate(
        db,
        select(InvestigationNote)
        .where(InvestigationNote.alert_id == alert_id)
        .order_by(InvestigationNote.id),
        page=page,
        page_size=page_size,
    )
    return {
        "success": True,
        "notes": [_serialize_note(note) for note in rows],
        "pagination": pagination,
    }


@router.get("/alerts/{alert_id}/investigation/history")
def history(
    alert_id: int,
    after_id: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    user: User = Depends(read_role),
    db: Session = Depends(get_db),
):
    locked(db, Alert, alert_id)
    return history_page(
        db, WorkflowEvent.alert_id == alert_id, after_id=after_id, limit=limit
    )
