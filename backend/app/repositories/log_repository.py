from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy.orm import Session

from app.models.log import Log


def parse_event_timestamp(value) -> datetime | None:
    """Parse parser timestamp values into timezone-aware datetimes when possible."""

    if value in (None, ""):
        return None

    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)

    if not isinstance(value, str):
        return None

    normalized = value.strip()
    if not normalized:
        return None

    try:
        if normalized.endswith("Z"):
            normalized = f"{normalized[:-1]}+00:00"
        parsed = datetime.fromisoformat(normalized)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def create_logs_from_parse_result(
    db: Session,
    *,
    upload_id: UUID,
    source_filename: str,
    parsed_result: dict,
) -> list[Log]:
    logs: list[Log] = []
    source_format = parsed_result.get("format") or "unknown"

    for entry in parsed_result.get("entries", []):
        parsed = entry.get("parsed") or {}
        log = Log(
            upload_id=upload_id,
            source_filename=source_filename,
            source_format=source_format,
            line_number=entry["line_number"],
            event_timestamp=parse_event_timestamp(parsed.get("timestamp")),
            ip_address=parsed.get("ip_address") or None,
            username=parsed.get("username") or None,
            event_type=parsed.get("event_type") or "security_event",
            status=parsed.get("status") or "UNKNOWN",
            severity=parsed.get("severity") or parsed.get("level"),
            raw_message=entry.get("raw") or "",
            parsed_data=parsed,
        )
        db.add(log)
        logs.append(log)

    db.flush()
    return logs
