from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
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
    find_by_external_id,
    get_custom_rule,
    list_custom_rules,
    next_rule_id,
    serialize_custom_rule,
    update_custom_rule,
)
from app.repositories.correlation_repository import normalized_log
from app.repositories.log_repository import list_recent_logs
from app.schemas.custom_rule import (
    ConditionPayload,
    CustomRuleCreate,
    CustomRuleTestRequest,
    CustomRuleUpdate,
    SigmaImportRequest,
)
from app.security import require_roles
from app.services.audit import record_audit
from app.services.sigma_import import SigmaUnsupported, parse_sigma, translate_rule

router = APIRouter(tags=["Custom Rules"])

TEST_SAMPLE_LIMIT = 5000
TEST_MATCH_PREVIEW = 5


def _log_to_record(log) -> LogRecord:
    """The full detection record for a stored event, exactly as an upload
    builds it, so a dry run can test every field a rule may use. The stored
    columns win where they exist; line_number carries the row id for the
    match preview."""

    record = normalized_log(log)
    return record.model_copy(update={
        "line_number": log.id,
        "timestamp": log.event_timestamp.isoformat() if log.event_timestamp else record.timestamp,
        "ip_address": str(log.ip_address) if log.ip_address is not None else record.ip_address,
        "username": log.username or record.username,
        "event_type": log.event_type or record.event_type,
        "status": log.status or record.status,
        "port": log.port if log.port is not None else record.port,
    })


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
    request: Request,
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
            conditions=[condition.to_storage() for condition in payload.conditions],
            group_by=payload.group_by,
            window_seconds=payload.window_seconds,
            actions=payload.actions,
            status=payload.status,
            dsl=payload.dsl,
            created_by=user.id,
            min_count=payload.min_count,
            mitre_technique=payload.mitre_technique,
        )
        record_audit(
            db,
            request,
            action="rule.custom.create",
            actor=user,
            target_type="custom_rule",
            target_id=rule.rule_id,
            target_label=rule.name,
            detail={"status": rule.status, "severity": rule.severity},
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


@router.post("/custom-rules/import/sigma")
def import_sigma_rules(
    payload: SigmaImportRequest,
    request: Request,
    user: User = Depends(require_roles("Admin", "Analyst")),
    db: Session = Depends(get_db),
):
    """Import Sigma rules (YAML, several separated by ---) as DRAFT custom rules.

    Every rule gets its own result: created (with the new rule id and any
    notes about how it was translated), skipped (already imported, by its
    Sigma id), or rejected (with the reason it cannot be expressed). Nothing
    is approximated silently.
    """

    try:
        documents = parse_sigma(payload.content)
    except SigmaUnsupported as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    results: list[dict] = []
    for label, document, yaml_error, source_text in documents:
        if yaml_error:
            results.append({"title": label, "status": "rejected", "reason": yaml_error})
            continue
        try:
            translated = translate_rule(document, source_text)
            # The same validation a hand-built rule goes through.
            conditions = [ConditionPayload.model_validate(item).to_storage() for item in translated.conditions]
        except SigmaUnsupported as exc:
            results.append({"title": label, "status": "rejected", "reason": f"Not imported: {exc}"})
            continue
        except ValueError as exc:
            results.append({"title": label, "status": "rejected", "reason": f"Not imported: {exc}"})
            continue

        if translated.external_id:
            existing = find_by_external_id(db, source="sigma", external_id=translated.external_id)
            if existing is not None:
                results.append({
                    "title": label,
                    "status": "skipped",
                    "rule_id": existing.rule_id,
                    "reason": f"Already imported as {existing.rule_id}.",
                })
                continue

        rule = create_custom_rule(
            db,
            name=translated.name,
            category="threat_hunting",
            severity=translated.severity,
            tactic=translated.tactic,
            conditions=conditions,
            group_by=translated.group_by,
            window_seconds=translated.window_seconds,
            actions={"create_alert": True, "notify_slack": False, "auto_incident": False, "suggest_playbook": False},
            status="DRAFT",
            dsl=translated.source_text,
            created_by=user.id,
            min_count=translated.min_count,
            mitre_technique=translated.mitre_technique,
            source="sigma",
            external_id=translated.external_id,
        )
        results.append({
            "title": label,
            "status": "created",
            "rule_id": rule.rule_id,
            "notes": translated.notes,
            "rule": serialize_custom_rule(rule),
        })

    counts = {state: sum(1 for item in results if item["status"] == state) for state in ("created", "skipped", "rejected")}
    record_audit(
        db,
        request,
        action="rule.custom.import",
        actor=user,
        target_type="custom_rule",
        detail={
            "format": "sigma",
            **counts,
            "rule_ids": [item["rule_id"] for item in results if item["status"] == "created"],
        },
    )
    try:
        db.commit()
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail="The imported rules could not be saved.") from exc

    return {"success": True, **counts, "results": results}


@router.patch("/custom-rules/{rule_pk}")
def patch_custom_rule(
    rule_pk: int,
    payload: CustomRuleUpdate,
    request: Request,
    user: User = Depends(require_roles("Admin", "Analyst")),
    db: Session = Depends(get_db),
):
    """Update, enable, disable, or archive-as-draft one custom rule."""

    updates = payload.model_dump(exclude_unset=True)
    if payload.conditions is not None:
        updates["conditions"] = [condition.to_storage() for condition in payload.conditions]

    try:
        rule = update_custom_rule(db, rule_pk=rule_pk, updates=updates)
        record_audit(
            db,
            request,
            action="rule.custom.update",
            actor=user,
            target_type="custom_rule",
            target_id=rule.rule_id,
            target_label=rule.name,
            detail={"fields": sorted(updates), "status": rule.status},
        )
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
    request: Request,
    user: User = Depends(require_roles("Admin", "Analyst")),
    db: Session = Depends(get_db),
):
    """Permanently delete one custom rule."""

    try:
        # Read the identity before the row is gone.
        doomed = get_custom_rule(db, rule_pk=rule_pk)
        rule_id, rule_name = doomed.rule_id, doomed.name
        delete_custom_rule(db, rule_pk=rule_pk)
        record_audit(
            db,
            request,
            action="rule.custom.delete",
            actor=user,
            target_type="custom_rule",
            target_id=rule_id,
            target_label=rule_name,
        )
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
        conditions=[condition.to_storage() for condition in payload.conditions],
        group_by=None if payload.group_by == "none" else payload.group_by,
        window_seconds=payload.window_seconds,
        min_count=payload.min_count,
        mitre_technique=payload.mitre_technique,
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
            "hostname": record.hostname,
            "process": record.process,
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
