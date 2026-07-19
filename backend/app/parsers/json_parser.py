from __future__ import annotations

import json
from typing import Any

from app.parsers.field_normalizer import CORE_FIELDS, first_ip, normalize_entry


CONTAINER_KEYS = ("events", "logs", "records", "results", "items", "data")


def _nested(record: dict[str, Any], path: str) -> Any:
    value: Any = record
    for key in path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def _pick(record: dict[str, Any], *paths: str) -> Any:
    for path in paths:
        value = _nested(record, path)
        # Container objects are useful for nested lookups but are not valid
        # normalized scalar fields (for example, {"user": {"name": "sam"}}).
        if value not in (None, "") and not isinstance(value, (dict, list)):
            return value
    return None


def _records_from_document(document: Any) -> list[Any]:
    if isinstance(document, list):
        return document
    if isinstance(document, dict):
        for key in CONTAINER_KEYS:
            value = document.get(key)
            if isinstance(value, list):
                return value
        return [document]
    return []


def parse_json_log(content: str, lines: list[str]) -> dict:
    """Parse JSON arrays/objects and newline-delimited JSON security exports."""

    skipped: list[dict] = []
    try:
        records = _records_from_document(json.loads(content))
    except json.JSONDecodeError:
        records = []
        for line_number, line in enumerate(content.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                records.extend(_records_from_document(json.loads(line)))
            except json.JSONDecodeError as exc:
                skipped.append({
                    "line_number": line_number,
                    "reason": f"Invalid JSON: {exc.msg}",
                    "raw": line[:500],
                })

    entries: list[dict] = []
    for index, record in enumerate(records, start=1):
        if not isinstance(record, dict):
            skipped.append({
                "line_number": index,
                "reason": "JSON event must be an object.",
                "raw": json.dumps(record, ensure_ascii=False)[:500],
            })
            continue

        raw = json.dumps(record, ensure_ascii=False, separators=(",", ":"))
        source_ip = _pick(
            record,
            "ip_address", "source_ip", "src_ip", "src", "client_ip",
            "remote_addr", "ip", "source.ip", "client.ip",
        ) or first_ip(raw)
        message = _pick(record, "message", "raw_message", "description", "_raw") or raw
        parsed = {
            **normalize_entry(
                timestamp=_pick(record, "timestamp", "@timestamp", "_time", "event_time", "time", "date", "created_at"),
                ip_address=source_ip,
                username=_pick(record, "username", "user", "user_name", "account", "principal", "user.name"),
                event_type=_pick(record, "event_type", "event", "action", "activity", "type", "event.action", "event.category"),
                status=_pick(record, "status", "result", "outcome", "verdict", "event.outcome"),
            ),
            "severity": _pick(record, "severity", "level", "log.level"),
            "message": str(message),
            "json": record,
        }
        entries.append({"line_number": index, "raw": raw, "parsed": parsed})

    return {
        "format": "json",
        "fields": CORE_FIELDS + ["severity", "message", "json"],
        "total_lines": len(lines),
        "entries": entries,
        "skipped_lines": skipped,
    }
