from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.alert import Alert
from app.models.correlation import (
    AlertEventLink,
    CorrelationGroup,
    CorrelationGroupAlert,
    CorrelationGroupEvent,
    CorrelationGroupUpload,
)
from app.models.log import Log
from app.models.upload_batch import UploadBatch
from app.models.user import User
from app.repositories.alert_repository import serialize_alert_record
from app.repositories.correlation_repository import (
    group_payloads,
    paginate,
    serialize_event,
)
from app.repositories.upload_batch_repository import serialize_upload_batch
from app.security import require_roles

router = APIRouter(tags=["Correlation and evidence"])
read_role = require_roles("Admin", "Analyst", "Viewer")


def require_record(db, model, identity):
    record = db.get(model, identity)
    if record is None:
        raise HTTPException(404, f"{model.__name__} {identity} does not exist.")
    return record


@router.get("/correlation-groups")
def list_groups(
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    entity_type: Literal["source_ip", "account", "host", "upload_batch"] | None = None,
    entity_value: str | None = Query(None, max_length=255),
    rule: str | None = Query(None, max_length=100),
    start: datetime | None = None,
    end: datetime | None = None,
    user: User = Depends(read_role),
    db: Session = Depends(get_db),
):
    start = (
        start.replace(tzinfo=timezone.utc) if start and start.tzinfo is None else start
    )
    end = end.replace(tzinfo=timezone.utc) if end and end.tzinfo is None else end
    if start and end and start >= end:
        raise HTTPException(422, "The observation range end must follow its start.")
    query = select(CorrelationGroup)
    for column, value in (
        (CorrelationGroup.entity_type, entity_type),
        (CorrelationGroup.entity_value, entity_value),
        (CorrelationGroup.rule_key, rule),
    ):
        if value is not None:
            query = query.where(column == value)
    if start:
        query = query.where(CorrelationGroup.last_seen >= start)
    if end:
        query = query.where(CorrelationGroup.first_seen < end)
    groups, pagination = paginate(
        db,
        query.order_by(CorrelationGroup.first_seen.desc(), CorrelationGroup.id.desc()),
        page=page,
        page_size=page_size,
    )
    return {
        "success": True,
        "groups": group_payloads(db, groups),
        "pagination": pagination,
    }


@router.get("/correlation-groups/{group_id}")
def get_group(
    group_id: int, user: User = Depends(read_role), db: Session = Depends(get_db)
):
    group = require_record(db, CorrelationGroup, group_id)
    return {
        "success": True,
        "group": {**group_payloads(db, [group])[0], "rule_context": group.rule_context},
    }


@router.get("/correlation-groups/{group_id}/events")
def group_events(
    group_id: int,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    user: User = Depends(read_role),
    db: Session = Depends(get_db),
):
    require_record(db, CorrelationGroup, group_id)
    events, pagination = paginate(
        db,
        select(Log)
        .join(CorrelationGroupEvent, CorrelationGroupEvent.log_id == Log.id)
        .where(CorrelationGroupEvent.group_id == group_id)
        .order_by(Log.event_timestamp.asc().nulls_last(), Log.id.asc()),
        page=page,
        page_size=page_size,
    )
    return {
        "success": True,
        "events": [serialize_event(e) for e in events],
        "pagination": pagination,
    }


@router.get("/correlation-groups/{group_id}/alerts")
def group_alerts(
    group_id: int,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    user: User = Depends(read_role),
    db: Session = Depends(get_db),
):
    require_record(db, CorrelationGroup, group_id)
    alerts, pagination = paginate(
        db,
        select(Alert)
        .join(CorrelationGroupAlert, CorrelationGroupAlert.alert_id == Alert.id)
        .where(CorrelationGroupAlert.group_id == group_id)
        .order_by(Alert.id),
        page=page,
        page_size=page_size,
    )
    return {
        "success": True,
        "alerts": [serialize_alert_record(a) for a in alerts],
        "pagination": pagination,
    }


@router.get("/correlation-groups/{group_id}/uploads")
def group_uploads(
    group_id: int,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    user: User = Depends(read_role),
    db: Session = Depends(get_db),
):
    require_record(db, CorrelationGroup, group_id)
    uploads, pagination = paginate(
        db,
        select(UploadBatch)
        .join(
            CorrelationGroupUpload,
            CorrelationGroupUpload.upload_id == UploadBatch.upload_id,
        )
        .where(CorrelationGroupUpload.group_id == group_id)
        .order_by(UploadBatch.uploaded_at, UploadBatch.upload_id),
        page=page,
        page_size=page_size,
    )
    return {
        "success": True,
        "uploads": [serialize_upload_batch(u) for u in uploads],
        "pagination": pagination,
    }


@router.get("/correlation-groups/{group_id}/rule-context")
def group_rule(
    group_id: int, user: User = Depends(read_role), db: Session = Depends(get_db)
):
    return {
        "success": True,
        "rule_context": require_record(db, CorrelationGroup, group_id).rule_context,
    }


@router.get("/alerts/{alert_id}")
def alert_detail(
    alert_id: int, user: User = Depends(read_role), db: Session = Depends(get_db)
):
    return {
        "success": True,
        "alert": serialize_alert_record(require_record(db, Alert, alert_id)),
    }


@router.get("/alerts/{alert_id}/evidence")
def alert_evidence(
    alert_id: int,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    user: User = Depends(read_role),
    db: Session = Depends(get_db),
):
    alert = require_record(db, Alert, alert_id)
    events, pagination = paginate(
        db,
        select(Log)
        .join(AlertEventLink, AlertEventLink.log_id == Log.id)
        .where(AlertEventLink.alert_id == alert_id)
        .order_by(Log.event_timestamp.asc().nulls_last(), Log.id.asc()),
        page=page,
        page_size=page_size,
    )
    provenance = dict((alert.evidence or {}).get("provenance") or {})
    expected = max(alert.event_count, len(set(alert.matched_line_numbers or [])))
    return {
        "success": True,
        "events": [serialize_event(e) for e in events],
        "pagination": pagination,
        "completeness": {
            "expected_events": expected,
            "linked_events": pagination["total"],
            "complete": pagination["total"] >= expected
            and not provenance.get("missing_references", 0),
            "missing_references": provenance.get(
                "missing_references", max(0, expected - pagination["total"])
            ),
        },
    }


@router.get("/alerts/{alert_id}/correlation-groups")
def alert_groups(
    alert_id: int,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    user: User = Depends(read_role),
    db: Session = Depends(get_db),
):
    require_record(db, Alert, alert_id)
    groups, pagination = paginate(
        db,
        select(CorrelationGroup)
        .join(
            CorrelationGroupAlert, CorrelationGroupAlert.group_id == CorrelationGroup.id
        )
        .where(CorrelationGroupAlert.alert_id == alert_id)
        .order_by(CorrelationGroup.first_seen.desc(), CorrelationGroup.id.desc()),
        page=page,
        page_size=page_size,
    )
    return {
        "success": True,
        "groups": group_payloads(db, groups),
        "pagination": pagination,
    }
