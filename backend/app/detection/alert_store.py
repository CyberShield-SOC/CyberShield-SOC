from __future__ import annotations

from app.detection.models import Alert

_ALERTS: list[dict] = []

_RULE_TITLES = {
    "brute_force_login": "Possible brute-force login activity",
    "invalid_user_enumeration": "Possible username enumeration",
    "sudo_failure": "Repeated sudo authentication failures",
}


def serialize_alert(alert: Alert) -> dict:
    data = alert.model_dump() if hasattr(alert, "model_dump") else alert.dict()
    return {
        **data,
        "title": _RULE_TITLES.get(alert.rule, "Security alert"),
        "ip_address": alert.source_ip,
        "user": alert.username,
        "reason": alert.description,
        "timestamp_range": {
            "start": alert.first_seen,
            "end": alert.last_seen,
        },
    }


def replace_alerts(alerts: list[dict]) -> None:
    _ALERTS.clear()
    _ALERTS.extend(alerts)


def list_alerts() -> list[dict]:
    return list(_ALERTS)
