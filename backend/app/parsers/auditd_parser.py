"""
Raw Linux audit log parser (/var/log/audit/audit.log).

One kernel audit *event* is written as several records sharing the same
`msg=audit(epoch:serial)` stamp — SYSCALL, EXECVE, CWD, PATH, PROCTITLE, ...
Rules care about the event, not the individual record, so records are merged
into one entry per event: command line from EXECVE/PROCTITLE, file paths
from PATH, and syscall/exe/key/auid from SYSCALL.
"""

from __future__ import annotations

import re

from app.parsers.field_normalizer import CORE_FIELDS, normalize_entry
from app.parsers.structured_fields import parse_audit_record

AUDIT_LINE = re.compile(r"^(?:node=\S+\s+)?type=\w+\s+msg=audit\(\d+(?:\.\d+)?:\d+\):")

# Audit record types that describe a login/authentication outcome.
_AUTH_TYPES = {"USER_LOGIN", "USER_AUTH", "USER_START", "USER_ERR", "CRED_ACQ"}


def looks_like_auditd(lines: list[str]) -> bool:
    sample = [line for line in lines[:10] if line.strip()]
    return bool(sample) and sum(1 for line in sample if AUDIT_LINE.match(line)) >= max(1, len(sample) // 2)


def _event_type(types: list[str], fields: dict) -> str:
    if "EXECVE" in types:
        return "process_execution"
    if "PATH" in types:
        return "file_activity"
    if set(types) & _AUTH_TYPES:
        return "login_attempt"
    if "MAC_STATUS" in types or "CONFIG_CHANGE" in types:
        return "security_config_change"
    return "audit_event"


def parse_auditd_log(content: str, lines: list[str]) -> dict:
    events: dict[str, dict] = {}
    order: list[str] = []
    skipped: list[dict] = []

    for index, line in enumerate(lines, start=1):
        record = parse_audit_record(line)
        if not record:
            skipped.append({"line_number": index, "reason": "Not an audit record", "raw": line})
            continue

        event_id = record["audit_event_id"]
        event = events.get(event_id)
        if event is None:
            event = {
                "line_number": index,
                "raw_lines": [],
                "types": [],
                "paths": [],
                "fields": {},
                "record": {},
            }
            events[event_id] = event
            order.append(event_id)

        event["raw_lines"].append(line)
        event["types"].append(record["audit_type"])
        fields = record["audit_fields"]
        if record["audit_type"] == "PATH":
            event["paths"].append({
                "name": record.get("file_path"),
                "nametype": fields.get("nametype"),
                "item": fields.get("item"),
            })
        else:
            # SYSCALL fields (syscall, success, exe, comm, key, a0-a3, auid)
            # win over later records' same-named keys.
            for key, value in fields.items():
                event["fields"].setdefault(key, value)
        for key in ("command", "audit_key", "username", "ip_address", "hostname"):
            if record.get(key) and not event["record"].get(key):
                event["record"][key] = record[key]
        event["record"].setdefault("timestamp", record["audit_timestamp"])
        event["record"]["audit_event_id"] = event_id

    entries = []
    for event_id in order:
        event = events[event_id]
        record = event["record"]
        fields = event["fields"]
        # The operated-on path is the last non-PARENT PATH item.
        target = next(
            (p for p in reversed(event["paths"]) if p["name"] and p["nametype"] != "PARENT"),
            None,
        )
        status = None
        if fields.get("success") in ("yes", "no"):
            status = "SUCCESS" if fields["success"] == "yes" else "FAILED"
        elif fields.get("res") in ("success", "failed"):
            status = "SUCCESS" if fields["res"] == "success" else "FAILED"

        entries.append({
            "line_number": event["line_number"],
            "raw": "\n".join(event["raw_lines"]),
            "parsed": {
                **normalize_entry(
                    timestamp=record.get("timestamp"),
                    ip_address=record.get("ip_address"),
                    username=record.get("username") or fields.get("acct"),
                    event_type=_event_type(event["types"], fields),
                    status=status,
                ),
                "hostname": record.get("hostname"),
                "process": fields.get("comm"),
                "message": " | ".join(event["raw_lines"])[:2000],
                "command": record.get("command"),
                "file_path": target["name"] if target else None,
                "audit_type": ",".join(dict.fromkeys(event["types"])),
                "audit_event_id": event_id,
                "audit_key": record.get("audit_key"),
                "audit_fields": fields,
                "audit_paths": event["paths"],
            },
        })

    return {
        "format": "auditd",
        "fields": CORE_FIELDS + ["hostname", "process", "command", "file_path", "audit_type", "audit_key"],
        "total_lines": len(lines),
        "entries": entries,
        "skipped_lines": skipped,
    }
