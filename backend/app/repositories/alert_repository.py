from __future__ import annotations

from ipaddress import ip_address
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.repositories.log_repository import parse_event_timestamp


class AlertNotFoundError(Exception):
    """Raised when the requested alert does not exist."""


def optional_text(value: Any) -> str | None:
    """Return stripped text or None."""

    if value is None:
        return None

    cleaned = str(value).strip()
    return cleaned or None


def optional_ip(value: Any) -> str | None:
    """Return a valid IPv4 or IPv6 address, otherwise None."""

    cleaned = optional_text(value)

    if cleaned is None:
        return None

    try:
        return str(ip_address(cleaned))
    except ValueError:
        return None


def create_alerts_from_detection(
    db: Session,
    *,
    upload_id: UUID,
    serialized_alerts: list[dict],
) -> list[Alert]:
    """
    Convert detection-engine output into persistent Alert records.

    Records are flushed but not committed. The upload route controls the
    transaction so logs and alerts succeed or fail together.
    """

    records: list[Alert] = []

    for alert_data in serialized_alerts:
        source_ip = (
            alert_data.get("source_ip")
            or alert_data.get("ip_address")
        )

        username = (
            alert_data.get("username")
            or alert_data.get("user")
        )

        description = (
            alert_data.get("description")
            or alert_data.get("reason")
            or "Security rule triggered."
        )

        matched_lines = [
            int(line_number)
            for line_number in (
                alert_data.get("matched_line_numbers") or []
            )
        ]

        record = Alert(
            upload_id=upload_id,
            rule=str(
                alert_data.get("rule")
                or "unknown_rule"
            ),
            title=str(
                alert_data.get("title")
                or "Security alert"
            ),
            severity=str(
                alert_data.get("severity")
                or "LOW"
            ).upper(),
            status="NEW",
            source_ip=optional_ip(source_ip),
            username=optional_text(username),
            event_count=int(
                alert_data.get("count") or 0
            ),
            time_window_seconds=int(
                alert_data.get("time_window_seconds") or 0
            ),
            first_seen=parse_event_timestamp(
                alert_data.get("first_seen")
            ),
            last_seen=parse_event_timestamp(
                alert_data.get("last_seen")
            ),
            description=str(description),
            matched_line_numbers=matched_lines,
        )

        records.append(record)

    db.add_all(records)
    db.flush()

    return records


def list_alert_records(
    db: Session,
    *,
    severity: str | None = None,
    status: str | None = None,
    limit: int = 100,
) -> list[Alert]:
    """Return newest alerts with optional filters."""

    statement = select(Alert)

    if severity:
        statement = statement.where(
            Alert.severity == severity.upper()
        )

    if status:
        statement = statement.where(
            Alert.status == status.upper()
        )

    statement = statement.order_by(
        Alert.created_at.desc(),
        Alert.id.desc(),
    ).limit(limit)

    return list(db.scalars(statement).all())


def update_alert_record(
    db: Session,
    *,
    alert_id: int,
    severity: str | None = None,
    status: str | None = None,
) -> Alert:
    """Update mutable alert workflow fields."""

    alert = db.get(Alert, alert_id)

    if alert is None:
        raise AlertNotFoundError(
            f"Alert {alert_id} does not exist."
        )

    if severity is not None:
        alert.severity = severity.upper()

    if status is not None:
        alert.status = status.upper()

    db.flush()

    return alert


def serialize_alert_record(alert: Alert) -> dict:
    """Convert a database Alert into the current API response format."""

    first_seen = (
        alert.first_seen.isoformat()
        if alert.first_seen
        else None
    )

    last_seen = (
        alert.last_seen.isoformat()
        if alert.last_seen
        else None
    )

    source_ip = (
        str(alert.source_ip)
        if alert.source_ip is not None
        else None
    )

    return {
        "id": alert.id,
        "upload_id": str(alert.upload_id),
        "rule": alert.rule,
        "title": alert.title,
        "severity": alert.severity,
        "status": alert.status,
        "source_ip": source_ip,
        "ip_address": source_ip,
        "username": alert.username,
        "user": alert.username,
        "count": alert.event_count,
        "time_window_seconds": alert.time_window_seconds,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "timestamp_range": {
            "start": first_seen,
            "end": last_seen,
        },
        "description": alert.description,
        "reason": alert.description,
        "matched_line_numbers": alert.matched_line_numbers,
        "created_at": alert.created_at.isoformat(),
        "updated_at": alert.updated_at.isoformat(),
    }
