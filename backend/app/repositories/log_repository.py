from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from sqlalchemy.orm import Session

from app.models.log import Log


def parse_event_timestamp(value: Any) -> datetime | None:
    """
    Convert a parser timestamp into a timezone-aware datetime.

    Invalid or unsupported timestamps return None. The original value remains
    available inside parsed_data, so no parser information is discarded.
    """

    if value is None:
        return None

    if isinstance(value, datetime):
        parsed_timestamp = value
    else:
        timestamp_text = str(value).strip()

        if not timestamp_text:
            return None

        if timestamp_text.endswith("Z"):
            timestamp_text = timestamp_text[:-1] + "+00:00"

        try:
            parsed_timestamp = datetime.fromisoformat(timestamp_text)
        except ValueError:
            return None

    if parsed_timestamp.tzinfo is None:
        parsed_timestamp = parsed_timestamp.replace(tzinfo=timezone.utc)

    return parsed_timestamp.astimezone(timezone.utc)


def optional_text(value: Any) -> str | None:
    """Convert a nonempty parser value to text."""

    if value is None:
        return None

    cleaned = str(value).strip()
    return cleaned or None


def create_logs_from_parse_result(
    db: Session,
    *,
    upload_id: UUID,
    source_filename: str,
    parsed_result: dict,
) -> list[Log]:
    """
    Convert parser entries into SQLAlchemy Log records.

    This function adds and flushes records but does not commit the transaction.
    The calling service or route controls commit and rollback.
    """

    source_format = str(
        parsed_result.get("format") or "unknown"
    )

    records: list[Log] = []

    for entry in parsed_result.get("entries", []):
        parsed_data = dict(entry.get("parsed") or {})

        severity = optional_text(
            parsed_data.get("severity")
            or parsed_data.get("level")
        )

        record = Log(
            upload_id=upload_id,
            source_filename=source_filename,
            source_format=source_format,
            line_number=int(entry["line_number"]),
            event_timestamp=parse_event_timestamp(
                parsed_data.get("timestamp")
            ),
            ip_address=optional_text(
                parsed_data.get("ip_address")
            ),
            username=optional_text(
                parsed_data.get("username")
            ),
            event_type=(
                optional_text(parsed_data.get("event_type"))
                or "security_event"
            ),
            status=(
                optional_text(parsed_data.get("status"))
                or "UNKNOWN"
            ).upper(),
            severity=severity.upper() if severity else None,
            raw_message=str(entry.get("raw") or ""),
            parsed_data=parsed_data,
        )

        records.append(record)

    db.add_all(records)
    db.flush()

    return records