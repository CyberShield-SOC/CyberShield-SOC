import re
from datetime import datetime
from app.parsers.field_normalizer import (
    CORE_FIELDS,
    event_type_from_text,
    first_ip,
    normalize_entry,
    status_from_text,
    username_from_text,
)
from app.parsers.structured_fields import extract_from_message

# Jan 10 08:00:01 server01 sshd[1234]: message
_SYSLOG_RE = re.compile(
    r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^\[:\s]+)(?:\[(\d+)\])?:\s+(.*)$'
)

_SEVERITY_KEYWORDS = {
    "CRITICAL": ["critical", "crit"],
    "ERROR":    ["error", "err"],
    "WARNING":  ["warning", "warn", "failed", "failure", "invalid", "denied"],
    "INFO":     ["info", "accepted", "started", "stopped"],
    "DEBUG":    ["debug"],
}

# Structured keys that replace the heuristic text-derived core fields when a
# message format is recognised (e.g. a firewall line's SRC is the source IP,
# not merely the first IP-looking token).
_CORE_OVERRIDES = ("ip_address", "username", "event_type", "status")


def parse_syslog(content: str, lines: list[str]) -> dict:
    entries = []
    skipped = []

    for idx, line in enumerate(lines):
        if line.startswith("#"):
            continue
        m = _SYSLOG_RE.match(line)
        if not m:
            skipped.append({"line_number": idx + 1, "reason": "No regex match", "raw": line})
            continue

        ts_raw, hostname, process, pid, message = m.groups()
        process = process.strip()
        message = message.strip()

        structured = extract_from_message(process, message)
        core = {
            "timestamp": _normalize_date(ts_raw),
            "ip_address": first_ip(message),
            "username": username_from_text(message),
            "event_type": event_type_from_text(message),
            "status": status_from_text(message),
        }
        for key in _CORE_OVERRIDES:
            if structured.get(key):
                core[key] = structured[key]

        extra = {
            key: value
            for key, value in structured.items()
            if key not in _CORE_OVERRIDES and key != "hostname"
        }

        entries.append({
            "line_number": idx + 1,
            "raw": line,
            "parsed": {
                **normalize_entry(**core),
                "hostname": hostname,
                "process": process,
                "pid": int(pid) if pid else None,
                "message": message,
                "severity": _detect_severity(message),
                **extra,
            },
        })

    return {
        "format": "syslog",
        "fields": CORE_FIELDS + ["hostname", "process", "pid", "message", "severity"],
        "total_lines": len(lines),
        "entries": entries,
        "skipped_lines": skipped,
    }


def _normalize_date(raw: str) -> str:
    """'Jan 10 08:00:01' → ISO string (assumes current year)."""
    try:
        year = datetime.now().year
        return datetime.strptime(f"{raw} {year}", "%b %d %H:%M:%S %Y").isoformat() + "Z"
    except Exception:
        return raw


def _detect_severity(message: str) -> str:
    msg = message.lower()
    for level, keywords in _SEVERITY_KEYWORDS.items():
        if any(kw in msg for kw in keywords):
            return level
    return "UNKNOWN"
