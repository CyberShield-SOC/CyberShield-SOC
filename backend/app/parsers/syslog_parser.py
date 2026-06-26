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

        timestamp = _normalize_date(ts_raw)
        ip_address = first_ip(message)
        username = username_from_text(message)
        event_type = event_type_from_text(message)
        status = status_from_text(message)

        entries.append({
            "line_number": idx + 1,
            "raw": line,
            "parsed": {
                **normalize_entry(
                    timestamp=timestamp,
                    ip_address=ip_address,
                    username=username,
                    event_type=event_type,
                    status=status,
                ),
                "hostname": hostname,
                "process": process.strip(),
                "pid": int(pid) if pid else None,
                "message": message.strip(),
                "severity": _detect_severity(message),
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
