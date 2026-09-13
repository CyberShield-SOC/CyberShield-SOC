from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.detection.models import LogRecord
from app.detection.rules.custom_condition import CustomConditionRule
from app.models.user import User
from app.repositories.custom_rule_repository import (
    CustomRuleNotFoundError,
    create_custom_rule,
    delete_custom_rule,
    list_custom_rules,
    next_rule_id,
    serialize_custom_rule,
    update_custom_rule,
)
from app.repositories.log_repository import list_recent_logs
from app.schemas.custom_rule import CustomRuleCreate, CustomRuleTestRequest, CustomRuleUpdate
from app.security import require_roles

router = APIRouter(tags=["Custom Rules"])

TEST_SAMPLE_LIMIT = 5000
TEST_MATCH_PREVIEW = 5


def _log_to_record(log) -> LogRecord:
    return LogRecord(
        line_number=log.id,
        timestamp=log.event_timestamp.isoformat() if log.event_timestamp else None,
        ip_address=str(log.ip_address) if log.ip_address is not None else None,
        username=log.username,
        event_type=log.event_type,
        status=log.status,
        port=log.port,
    )


@router.get("/custom-rules")
def get_custom_rules(
    user: User = Depends(require_roles("Admin", "Analyst", "Viewer")),
    db: Session = Depends(get_db),
):
    """Return every custom rule, newest first, plus the next auto-assigned id."""

    rules = list_custom_rules(db)
    return {
        "success": True,
        "count": len(rules),
        "rules": [serialize_custom_rule(rule) for rule in rules],
        "next_rule_id": next_rule_id(db),
    }


@router.post("/custom-rules", status_code=status.HTTP_201_CREATED)
def post_custom_rule(
    payload: CustomRuleCreate,
    user: User = Depends(require_roles("Admin", "Analyst")),
    db: Session = Depends(get_db),
):
    """Author a new custom detection rule that runs alongside R-101..R-108."""

    try:
        rule = create_custom_rule(
            db,
            name=payload.name,
            category=payload.category,
            severity=payload.severity,
            tactic=payload.tactic,
            conditions=[condition.model_dump() for condition in payload.conditions],
            group_by=payload.group_by,
            window_seconds=payload.window_seconds,
            actions=payload.actions,
            status=payload.status,
            dsl=payload.dsl,
            created_by=user.id,
        )
        db.commit()
        db.refresh(rule)
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Custom rule could not be saved.",
        ) from exc

    return {"success": True, "rule": serialize_custom_rule(rule)}


@router.patch("/custom-rules/{rule_pk}")
def patch_custom_rule(
    rule_pk: int,
    payload: CustomRuleUpdate,
    user: User = Depends(require_roles("Admin", "Analyst")),
    db: Session = Depends(get_db),
):
    """Update, enable, disable, or archive-as-draft one custom rule."""

    updates = payload.model_dump(exclude_unset=True)

    try:
        rule = update_custom_rule(db, rule_pk=rule_pk, updates=updates)
        db.commit()
        db.refresh(rule)
    except CustomRuleNotFoundError as exc:
        db.rollback()
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Custom rule could not be updated.",
        ) from exc

    return {"success": True, "rule": serialize_custom_rule(rule)}


@router.delete("/custom-rules/{rule_pk}")
def remove_custom_rule(
    rule_pk: int,
    user: User = Depends(require_roles("Admin", "Analyst")),
    db: Session = Depends(get_db),
):
    """Permanently delete one custom rule."""

    try:
        delete_custom_rule(db, rule_pk=rule_pk)
        db.commit()
    except CustomRuleNotFoundError as exc:
        db.rollback()
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Custom rule could not be deleted.",
        ) from exc

    return {"success": True, "deleted_rule_id": rule_pk}


@router.post("/custom-rules/test")
def test_custom_rule(
    payload: CustomRuleTestRequest,
    user: User = Depends(require_roles("Admin", "Analyst")),
    db: Session = Depends(get_db),
):
    """Dry-run a rule draft against recently ingested logs without saving it."""

    logs = list_recent_logs(db, limit=TEST_SAMPLE_LIMIT)
    records = [_log_to_record(log) for log in logs]

    runner = CustomConditionRule(
        rule_id="R-DRAFT",
        display_name=payload.name,
        severity=payload.severity,
        conditions=[condition.model_dump() for condition in payload.conditions],
        group_by=None if payload.group_by == "none" else payload.group_by,
        window_seconds=payload.window_seconds,
    )

    raw_matches = runner.matches(records)
    alerts = runner.analyze(records)

    span_seconds = 0.0
    timestamps = [
        log.event_timestamp for log in logs if log.event_timestamp is not None
    ]
    if len(timestamps) >= 2:
        span_seconds = (max(timestamps) - min(timestamps)).total_seconds()
    span_days = max(span_seconds / 86400, 1 / 24)  # never divide by less than one hour

    alerts_per_day = round(len(alerts) / span_days, 1)
    if alerts_per_day < 1:
        noise_label = "LOW"
    elif alerts_per_day < 5:
        noise_label = "MEDIUM"
    else:
        noise_label = "HIGH"

    preview = []
    for record in raw_matches[:TEST_MATCH_PREVIEW]:
        preview.append({
            "timestamp": record.timestamp,
            "ip_address": record.ip_address,
            "username": record.username,
            "event_type": record.event_type,
            "status": record.status,
            "port": record.port,
            "line_number": record.line_number,
        })

    return {
        "success": True,
        "sampled_count": len(records),
        "match_count": len(raw_matches),
        "alert_count": len(alerts),
        "matches": preview,
        "noise": {
            "label": noise_label,
            "alerts_per_day": alerts_per_day,
        },
    }
