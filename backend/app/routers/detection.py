import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.session import get_db
from app.detection.alert_store import serialize_alert
from app.detection.engine import _RULE_CLASSES, DetectionEngine
from app.models.host_heartbeat import HostHeartbeat
from app.models.user import User
from app.repositories.alert_repository import (
    create_alerts_from_detection,
    serialize_alert_record,
    suppress_alerts_in_cooldown,
)
from app.repositories.detection_rule_setting_repository import (
    DetectionRuleNotFoundError,
    DetectionRuleSettingError,
    effective_rule_configs,
    upsert_rule_setting,
)
from app.schemas.detection_rule import DetectionRuleUpdate
from app.security import require_roles


router = APIRouter(tags=["Detection"])


def _rule_payload(rule_cls, config) -> dict:
    rule = rule_cls()
    return {
        "name": rule.name,
        "description": rule.description,
        "severity": rule.severity,
        "mitre_technique": rule.mitre_technique or None,
        "entity_type": rule.entity_type,
        "tunables": rule_cls.tunables(),
        "default_params": dict(rule_cls.DEFAULT_PARAMS),
        "config": config.model_dump(),
    }


@router.get("/detection/rules")
def get_detection_rules(
    user: User = Depends(require_roles("Admin", "Analyst", "Viewer")),
    db: Session = Depends(get_db),
):
    """Return Detection Engine v2 rule metadata and active thresholds.

    Active thresholds reflect, per rule, the class default overridden first
    by DETECTION_RULE_CONFIG and then by any admin-saved setting — the same
    precedence _run_upload_pipeline uses to build the engine.
    """

    configs = effective_rule_configs(db, settings.detection_rule_config)
    rules = [_rule_payload(rule_cls, configs[rule_cls().name]) for rule_cls in _RULE_CLASSES]
    return {"success": True, "rules": rules}


@router.patch("/detection/rules/{rule_name}")
def patch_detection_rule(
    rule_name: str,
    payload: DetectionRuleUpdate,
    user: User = Depends(require_roles("Admin", "Analyst")),
    db: Session = Depends(get_db),
):
    """Persist an enabled/threshold override for one built-in rule.

    Takes effect on the next upload — DetectionEngine is rebuilt per upload
    from the same effective_rule_configs this endpoint writes through.
    """

    updates = payload.model_dump(exclude_unset=True)
    if not updates:
        raise HTTPException(status_code=400, detail="No rule settings were provided.")

    try:
        upsert_rule_setting(db, rule_name=rule_name, updates=updates, updated_by=user.id)
        db.commit()
    except DetectionRuleNotFoundError as exc:
        db.rollback()
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except DetectionRuleSettingError as exc:
        db.rollback()
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail="Detection rule setting could not be saved.") from exc

    configs = effective_rule_configs(db, settings.detection_rule_config)
    rule_cls = next(cls for cls in _RULE_CLASSES if cls().name == rule_name)
    return {"success": True, "rule": _rule_payload(rule_cls, configs[rule_name])}


def _host_silence_rule(db: Session):
    from app.detection.rules.host_log_silence import HostLogSilenceRule

    configs = effective_rule_configs(db, settings.detection_rule_config)
    config = configs[HostLogSilenceRule.name]
    return DetectionEngine.rule_from_config(HostLogSilenceRule, config), config


@router.get("/detection/host-heartbeats")
def get_host_heartbeats(
    user: User = Depends(require_roles("Admin", "Analyst", "Viewer")),
    db: Session = Depends(get_db),
):
    """Every host that has sent logs, with its reporting status right now."""

    from app.detection.rules.host_log_silence import HostLogSilenceRule

    rule, _ = _host_silence_rule(db)
    rule = rule or HostLogSilenceRule()
    now = datetime.now(timezone.utc)
    hosts = []
    for row in db.scalars(select(HostHeartbeat).order_by(HostHeartbeat.hostname)).all():
        last_seen = row.last_seen_at if row.last_seen_at.tzinfo else row.last_seen_at.replace(tzinfo=timezone.utc)
        threshold = rule.silence_threshold(row.cadence_seconds)
        silent_for = max(0.0, (now - last_seen).total_seconds())
        if row.event_count < int(rule.params["min_events"]):
            status = "learning"
        elif silent_for > threshold:
            status = "silent"
        else:
            status = "reporting"
        hosts.append({
            "hostname": row.hostname,
            "status": status,
            "first_seen_at": row.first_seen_at.isoformat(),
            "last_seen_at": last_seen.isoformat(),
            "event_count": row.event_count,
            "cadence_seconds": round(row.cadence_seconds, 1) if row.cadence_seconds else None,
            "silence_threshold_seconds": int(threshold),
            "silent_for_seconds": int(silent_for),
        })
    return {"success": True, "checked_at": now.isoformat(), "hosts": hosts}


@router.post("/detection/host-silence/check")
def check_host_silence(
    user: User = Depends(require_roles("Admin", "Analyst")),
    db: Session = Depends(get_db),
):
    """Raise host_log_silence alerts against the current time.

    Upload-time checks only use the newest event in that upload as "now"; this
    endpoint lets an analyst — or an external cron job — find hosts that went
    quiet when nothing is being uploaded at all.
    """

    from app.detection.rules.host_log_silence import HostLogSilenceRule

    rule, config = _host_silence_rule(db)
    if rule is None:
        raise HTTPException(status_code=409, detail="The host_log_silence rule is disabled.")

    states = rule.load_states(db)
    findings = rule.ongoing_silences(states, datetime.now(timezone.utc))
    detection_alerts = suppress_alerts_in_cooldown(
        db, [rule.to_alert(finding) for finding in findings], {HostLogSilenceRule.name: config.cooldown_seconds}
    )
    try:
        saved = create_alerts_from_detection(
            db,
            upload_id=uuid.uuid4(),
            serialized_alerts=[serialize_alert(alert) for alert in detection_alerts],
        )
        rule.save_states(db, states)
        db.commit()
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail="Host silence results could not be saved.") from exc

    return {"success": True, "alerts": [serialize_alert_record(alert) for alert in saved]}
