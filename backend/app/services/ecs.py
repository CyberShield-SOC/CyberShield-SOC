"""Elastic Common Schema (ECS) export.

Maps stored events and alerts onto ECS field names so another SIEM can read
them without a custom mapping. Only fields with a value are emitted, and
anything that has no ECS home is kept under the ``cybershield`` namespace
rather than being squeezed into a field that means something else.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.repositories.correlation_repository import normalized_log

ECS_VERSION = "8.11.0"
EXPORT_ROW_LIMIT = 50_000

# event_type -> (event.category, event.type), using ECS's allowed values.
_EVENT_CLASSES: dict[str, tuple[list[str], list[str]]] = {
    "login_attempt": (["authentication"], ["start"]),
    "logout": (["authentication"], ["end"]),
    "privilege_escalation": (["process"], ["start"]),
    "process_execution": (["process"], ["start"]),
    "port_scan": (["network"], ["connection"]),
    "network_connection": (["network"], ["connection"]),
    "dns_query": (["network"], ["protocol"]),
    "file_access": (["file"], ["access"]),
    "web_request": (["web"], ["access"]),
}
_OUTCOMES = {"SUCCESS": "success", "FAILED": "failure"}
_ALERT_SEVERITY = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _prune(value: Any) -> Any:
    """Drop empty values so the document only states what is known."""

    if isinstance(value, dict):
        pruned = {key: _prune(item) for key, item in value.items()}
        return {key: item for key, item in pruned.items() if item not in (None, "", [], {})}
    if isinstance(value, list):
        return [item for item in (_prune(item) for item in value) if item not in (None, "", [], {})]
    return value


def _unique(*values: Any) -> list:
    seen: list = []
    for value in values:
        if value not in (None, "") and value not in seen:
            seen.append(value)
    return seen


def _geo(record) -> dict:
    country = (record.country or "").strip()
    geo: dict[str, Any] = {}
    if len(country) == 2 and country.isalpha():
        geo["country_iso_code"] = country.upper()
    elif country:
        geo["country_name"] = country
    if record.latitude is not None and record.longitude is not None:
        geo["location"] = {"lat": record.latitude, "lon": record.longitude}
    return geo


def _pid(parsed_data: dict | None) -> int | None:
    value = (parsed_data or {}).get("pid")
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def event_to_ecs(log) -> dict:
    """One stored log row (or a row-like with the same attributes) as ECS."""

    record = normalized_log(log)
    category, kind_type = _EVENT_CLASSES.get(log.event_type or "", ([], ["info"]))
    severity = (log.severity or "").strip().lower()
    asn = (record.asn or "").upper().removeprefix("AS")

    return _prune({
        "@timestamp": _iso(log.event_timestamp) or _iso(log.ingested_at),
        "ecs": {"version": ECS_VERSION},
        "message": record.message or log.raw_message,
        "event": {
            "id": str(log.id),
            "kind": "event",
            "category": category,
            "type": kind_type,
            "action": log.event_type,
            "outcome": _OUTCOMES.get((log.status or "").upper(), "unknown"),
            "dataset": f"cybershield.{log.source_format}",
            "module": "cybershield",
            "ingested": _iso(log.ingested_at),
            "original": log.raw_message,
        },
        "log": {
            "level": severity if severity and severity != "unknown" else None,
            "file": {"path": log.source_filename},
        },
        "source": {
            "ip": record.ip_address,
            "bytes": record.bytes_out,
            "geo": _geo(record),
            "as": {"number": int(asn)} if asn.isdigit() else None,
        },
        "destination": {
            "ip": record.dest_ip,
            "port": record.port,
            "domain": record.domain,
            "bytes": record.bytes_in,
        },
        "user": {"name": record.username},
        "host": {"name": record.hostname},
        "process": {
            "name": record.process,
            "pid": _pid(log.parsed_data),
            "command_line": record.command,
        },
        "file": {"path": record.file_path},
        "network": {"transport": record.protocol.lower() if record.protocol else None},
        "dns": {"question": {"name": record.dns_query, "type": record.dns_query_type}},
        "related": {
            "ip": _unique(record.ip_address, record.dest_ip),
            "user": _unique(record.username),
            "hosts": _unique(record.hostname, record.domain),
        },
        "cybershield": {
            "upload_id": str(log.upload_id),
            "line_number": log.line_number,
            "source_format": log.source_format,
        },
    })


def alert_to_ecs(alert) -> dict:
    """One stored alert as an ECS alert document."""

    technique = (alert.mitre_technique or "").strip().upper()
    parent, _, sub = technique.partition(".")
    source_ip = str(alert.source_ip) if alert.source_ip is not None else None

    return _prune({
        "@timestamp": _iso(alert.last_seen) or _iso(alert.created_at),
        "ecs": {"version": ECS_VERSION},
        "message": alert.description,
        "event": {
            "id": str(alert.id),
            "kind": "alert",
            "category": ["intrusion_detection"],
            "type": ["info"],
            "action": alert.rule,
            "severity": _ALERT_SEVERITY.get((alert.severity or "").upper()),
            "risk_score": alert.confidence,
            "created": _iso(alert.created_at),
            "start": _iso(alert.first_seen),
            "end": _iso(alert.last_seen),
            "dataset": "cybershield.alert",
            "module": "cybershield",
        },
        "log": {"level": (alert.severity or "").lower()},
        "rule": {
            "id": alert.rule,
            "name": alert.title,
            "description": alert.description,
        },
        "threat": {
            "framework": "MITRE ATT&CK" if technique else None,
            "technique": {
                "id": [parent] if parent else [],
                "reference": [f"https://attack.mitre.org/techniques/{parent}/"] if parent else [],
                "subtechnique": {"id": [technique] if sub else []},
            },
        },
        "source": {"ip": source_ip},
        "user": {"name": alert.username},
        "host": {"name": alert.hostname},
        "related": {
            "ip": _unique(source_ip),
            "user": _unique(alert.username),
            "hosts": _unique(alert.hostname),
        },
        "cybershield": {
            "upload_id": str(alert.upload_id),
            "status": alert.status,
            "investigation_state": alert.investigation_state,
            "event_count": alert.event_count,
            "time_window_seconds": alert.time_window_seconds,
            "matched_line_numbers": alert.matched_line_numbers,
            "entity_type": alert.entity_type,
        },
    })
