from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

import httpx

from app.models.alert import Alert


def build_slack_alert_payload(
    alert: Alert, playbook: dict[str, Any] | None = None
) -> dict:
    """Build the webhook body for a triggered alert notification."""

    text = f"[{alert.severity}] {alert.title}: {alert.description}"
    fields = [
        {"title": "Rule", "value": alert.rule, "short": True},
        {"title": "Count", "value": str(alert.event_count), "short": True},
    ]
    if alert.source_ip:
        fields.append(
            {"title": "Source IP", "value": str(alert.source_ip), "short": True}
        )
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

    try:
        url = urlsplit(webhook_url)
        if url.scheme != "https" or not url.hostname or url.username or url.password:
            return {"status": "failed", "error": "Invalid Slack webhook URL"}
        response = httpx.post(
            webhook_url,
            json=payload,
            timeout=timeout_seconds,
            follow_redirects=False,
        )
        response.raise_for_status()
        return {"status": "sent", "status_code": response.status_code}
    except (httpx.HTTPError, ValueError):
        return {"status": "failed", "error": "Slack webhook delivery failed"}
