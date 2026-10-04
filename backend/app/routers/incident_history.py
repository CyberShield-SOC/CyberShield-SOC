from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.alert import Alert
from app.models.incident import Incident
from app.models.user import User
from app.models.workflow import IncidentAlertLink, WorkflowEvent
from app.repositories.alert_repository import serialize_alert_record
from app.repositories.correlation_repository import paginate
from app.repositories.incident_repository import serialize_incident_record
from app.security import require_roles
from app.services.incident_workflow import ACTIVE, TERMINAL, link_alert, update_incident
from app.services.workflow import (
    commit_workflow,
    history_page,
    locked,
    workflow_transaction,
)

router = APIRouter(tags=["Incident lifecycle"])
read_role = require_roles("Admin", "Analyst", "Viewer")
write_role = require_roles("Admin", "Analyst")


class Resolve(BaseModel):
    model_config = ConfigDict(extra="forbid")
    outcome: Literal["RESOLVED", "FALSE_POSITIVE"] = "RESOLVED"
    reason: str = Field(min_length=1, max_length=2000)
    note: str = Field(min_length=1, max_length=5000)
    expected_version: int | None = Field(None, gt=0)

    @field_validator("reason", "note")
    @classmethod
    def nonblank(cls, value):
        if not value.strip():
            raise ValueError("Provide a nonblank reason and note.")
        return value.strip()


class Reopen(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(min_length=1, max_length=2000)
    state: Literal["OPEN", "INVESTIGATING"] = "INVESTIGATING"
    expected_version: int | None = Field(None, gt=0)
    _normalize = field_validator("reason")(Resolve.nonblank.__func__)


class LinkAlert(BaseModel):
    model_config = ConfigDict(extra="forbid")
    alert_id: int = Field(gt=0)
    expected_version: int | None = Field(None, gt=0)


@router.post("/incidents/{incident_id}/resolve")
@workflow_transaction
def resolve(
    incident_id: int,
    payload: Resolve,
    user: User = Depends(write_role),
    db: Session = Depends(get_db),
):
    incident = locked(db, Incident, incident_id)
    if incident.status not in ACTIVE:
        raise HTTPException(409, "Only an open incident can be resolved.")
    incident = update_incident(
        db,
        incident_id,
        {
            "status": payload.outcome,
            "resolution_reason": payload.reason,
            "resolution_note": payload.note,
            "expected_version": payload.expected_version,
        },
        user.id,
    )
    commit_workflow(db)
    return {"success": True, "incident": serialize_incident_record(incident)}


@router.post("/incidents/{incident_id}/reopen")
@workflow_transaction
def reopen(
    incident_id: int,
    payload: Reopen,
    user: User = Depends(write_role),
    db: Session = Depends(get_db),
):
    incident = locked(db, Incident, incident_id)
    if incident.status not in TERMINAL:
        raise HTTPException(
            409, "Only a resolved or false-positive incident can be reopened."
        )
    incident = update_incident(
        db,
        incident_id,
        {
            "status": payload.state,
            "reason": payload.reason,
            "expected_version": payload.expected_version,
        },
        user.id,
    )
    commit_workflow(db)
    return {"success": True, "incident": serialize_incident_record(incident)}


@router.get("/incidents/{incident_id}/history")
def history(
    incident_id: int,
    after_id: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    user: User = Depends(read_role),
    db: Session = Depends(get_db),
):
    locked(db, Incident, incident_id)
    return history_page(
        db, WorkflowEvent.incident_id == incident_id, after_id=after_id, limit=limit
    )


@router.get("/incidents/{incident_id}/alerts")
def alerts(
    incident_id: int,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    user: User = Depends(read_role),
    db: Session = Depends(get_db),
):
    locked(db, Incident, incident_id)
    rows, pagination = paginate(
        db,
        select(Alert)
        .join(IncidentAlertLink, IncidentAlertLink.alert_id == Alert.id)
        .where(IncidentAlertLink.incident_id == incident_id)
        .order_by(Alert.id),
        page=page,
        page_size=page_size,
    )
    return {
        "success": True,
        "alerts": [serialize_alert_record(a) for a in rows],
        "pagination": pagination,
    }


@router.post("/incidents/{incident_id}/alerts", status_code=201)
@workflow_transaction
def add_alert(
    incident_id: int,
    payload: LinkAlert,
    user: User = Depends(write_role),
    db: Session = Depends(get_db),
):
    incident = link_alert(
        db, incident_id, payload.alert_id, user.id, payload.expected_version
    )
    commit_workflow(db)
    return {"success": True, "incident": serialize_incident_record(incident)}


@router.delete("/incidents/{incident_id}/alerts/{alert_id}")
@workflow_transaction
def remove_alert(
    incident_id: int,
    alert_id: int,
    expected_version: int | None = Query(None, gt=0),
    user: User = Depends(write_role),
    db: Session = Depends(get_db),
):
    incident = link_alert(
        db, incident_id, alert_id, user.id, expected_version, remove=True
    )
    commit_workflow(db)
    return {"success": True, "incident": serialize_incident_record(incident)}
