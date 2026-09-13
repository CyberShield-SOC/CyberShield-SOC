from __future__ import annotations

from typing import Any, Callable

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.dispatch.slack import build_slack_alert_payload, dispatch_slack_webhook
from app.models.alert import Alert
from app.models.custom_rule import CustomRule
from app.models.incident import Incident
from app.repositories.incident_repository import (
    IncidentAlreadyExistsError,
    create_incident_from_alert,
)

DEFAULT_AUTO_INCIDENT_COUNT = 3
DEFAULT_AUTO_INCIDENT_WINDOW_SECONDS = 3600

PLAYBOOKS_BY_CATEGORY = {
    "generic_detection": {
        "id": "PB-01",
        "title": "General Alert Triage",
        "route": "/soc/incidents",
    },
    "threat_hunting": {
        "id": "PB-02",
        "title": "Threat Hunting Investigation",
        "route": "/soc/ai-analysis",
    },
    "emerging_threat": {
        "id": "PB-03",
        "title": "Emerging Threat Containment",
        "route": "/soc/quick-resolve",
    },
    "compliance": {
        "id": "PB-04",
        "title": "Compliance Evidence Review",
        "route": "/soc/analyst-notes",
    },
    "placeholder": {
        "id": "PB-00",
        "title": "Draft Rule Review",
        "route": "/soc/threat-detection",
    },
}

SlackDispatcher = Callable[..., dict]


def _enabled(value: Any) -> bool:
    if isinstance(value, dict):
        return bool(value.get("enabled", True))
    return bool(value)


def _config(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def playbook_for_rule(rule: CustomRule) -> dict[str, Any]:
    """Return stable response-playbook metadata for a custom rule."""

    playbook = dict(
        PLAYBOOKS_BY_CATEGORY.get(
            rule.category,
            PLAYBOOKS_BY_CATEGORY["generic_detection"],
        )
    )
    playbook["rule_id"] = rule.rule_id
    playbook["rule_name"] = rule.name
    if rule.tactic:
        playbook["mitre_tactic"] = rule.tactic
    return playbook


def _auto_incident_threshold(rule: CustomRule) -> tuple[int, int]:
    action_config = _config(rule.actions.get("auto_incident"))
    count = int(action_config.get("threshold_count") or DEFAULT_AUTO_INCIDENT_COUNT)
    seconds = int(
        action_config.get("window_seconds")
        or action_config.get("threshold_window_seconds")
        or DEFAULT_AUTO_INCIDENT_WINDOW_SECONDS
    )
    return max(1, count), max(60, seconds)


def _within_threshold_window(alert: Alert, threshold_seconds: int) -> bool:
    window = int(alert.time_window_seconds or 0)
    if window > 0:
        return window <= threshold_seconds
    if alert.first_seen and alert.last_seen:
        return (alert.last_seen - alert.first_seen).total_seconds() <= threshold_seconds
    return True


def _eligible_for_auto_incident(alert: Alert, rule: CustomRule) -> bool:
    threshold_count, threshold_seconds = _auto_incident_threshold(rule)
    return (
        alert.event_count >= threshold_count
        and _within_threshold_window(alert, threshold_seconds)
    )


def apply_custom_rule_actions(
    db: Session,
    *,
    alerts: list[Alert],
    custom_rules: list[CustomRule],
    slack_webhook_url: str | None = None,
    slack_dispatcher: SlackDispatcher = dispatch_slack_webhook,
) -> dict[str, Any]:
    """
    Apply post-alert actions for enabled custom rules.

    Alerts, incidents, and action metadata are flushed but not committed; the
    upload route owns the surrounding transaction.
    """

    rules_by_id = {rule.rule_id: rule for rule in custom_rules}
    summary: dict[str, Any] = {
        "auto_incidents_created": 0,
        "slack_notifications": {"sent": 0, "skipped": 0, "failed": 0},
    }

    for alert in alerts:
        rule = rules_by_id.get(alert.rule)
        if rule is None:
            continue

        results = dict(alert.action_results or {})
        playbook = playbook_for_rule(rule) if _enabled(rule.actions.get("suggest_playbook")) else {}
        if playbook:
            alert.response_playbook = playbook
            results["suggest_playbook"] = {"status": "linked", "playbook_id": playbook["id"]}

        if _enabled(rule.actions.get("auto_incident")):
            if _eligible_for_auto_incident(alert, rule):
                try:
                    incident = create_incident_from_alert(db, alert_id=alert.id)
                    if playbook:
                        incident.response_playbook = playbook
                    results["auto_incident"] = {
                        "status": "created",
                        "incident_id": incident.id,
                    }
                    summary["auto_incidents_created"] += 1
                except IncidentAlreadyExistsError:
                    existing = db.scalar(
                        select(Incident.id).where(Incident.source_alert_id == alert.id)
                    )
                    results["auto_incident"] = {
                        "status": "already_exists",
                        "incident_id": existing,
                    }
            else:
                threshold_count, threshold_seconds = _auto_incident_threshold(rule)
                results["auto_incident"] = {
                    "status": "threshold_not_met",
                    "threshold_count": threshold_count,
                    "threshold_window_seconds": threshold_seconds,
                }

        if _enabled(rule.actions.get("notify_slack")):
            slack_result = slack_dispatcher(
                webhook_url=slack_webhook_url,
                payload=build_slack_alert_payload(alert, playbook),
            )
            status = slack_result.get("status", "failed")
            if status not in summary["slack_notifications"]:
                status = "failed"
            summary["slack_notifications"][status] += 1
            results["notify_slack"] = slack_result

        alert.action_results = results

    db.flush()
    return summary
