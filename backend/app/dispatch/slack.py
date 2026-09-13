from __future__ import annotations

import json
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen

from app.models.alert import Alert


def build_slack_alert_payload(alert: Alert, playbook: dict[str, Any] | None = None) -> dict:
    """Build the webhook body for a triggered alert notification."""

    text = f"[{alert.severity}] {alert.title}: {alert.description}"
    fields = [
        {"title": "Rule", "value": alert.rule, "short": True},
        {"title": "Count", "value": str(alert.event_count), "short": True},
    ]
    if alert.source_ip:
        fields.append({"title": "Source IP", "value": str(alert.source_ip), "short": True})
    if alert.username:
        fields.append({"title": "User", "value": alert.username, "short": True})
    if playbook:
        fields.append(
            {
                "title": "Playbook",
                "value": f"{playbook.get('id', 'PB')} - {playbook.get('title', 'Response playbook')}",
                "short": False,
            }
        )

    return {
        "text": text,
        "attachments": [
            {
                "color": {
                    "LOW": "#3b82f6",
                    "MEDIUM": "#f59e0b",
                    "HIGH": "#f97316",
                    "CRITICAL": "#dc2626",
                }.get(alert.severity, "#6b7280"),
                "fields": fields,
            }
        ],
    }


def dispatch_slack_webhook(
    *,
    webhook_url: str | None,
    payload: dict,
    timeout_seconds: float = 2.0,
) -> dict:
    """Send a Slack webhook if configured; otherwise report a skipped dispatch."""

    if not webhook_url:
        return {"status": "skipped", "reason": "slack_webhook_url_not_configured"}

    body = json.dumps(payload).encode("utf-8")
    request = Request(
        webhook_url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            return {"status": "sent", "status_code": response.status}
    except (OSError, URLError) as exc:
        return {"status": "failed", "error": str(exc)[:200]}
