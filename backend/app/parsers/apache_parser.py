import re
from datetime import datetime, timezone
from app.parsers.field_normalizer import CORE_FIELDS, normalize_entry, status_from_http_code

# 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 2326 "ref" "UA"
_APACHE_RE = re.compile(
    r'^(\S+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+"([^"]+)"\s+(\d{3})\s+(\S+)'
    r'(?:\s+"([^"]*)"\s+"([^"]*)")?'
)

_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def parse_apache_log(content: str, lines: list[str]) -> dict:
    entries = []
    skipped = []

    for idx, line in enumerate(lines):
        m = _APACHE_RE.match(line)
        if not m:
            skipped.append({"line_number": idx + 1, "reason": "No regex match", "raw": line})
            continue

        ip, ident, user, ts_raw, request, status, bytes_str, referer, user_agent = m.groups()
        method, path, protocol = (request + " ").split(" ", 2)[:3]

        timestamp = _parse_apache_date(ts_raw)
        status_code = int(status)

        entries.append({
            "line_number": idx + 1,
            "raw": line,
            "parsed": {
                **normalize_entry(
                    timestamp=timestamp,
                    ip_address=ip,
                    username=None if user == "-" else user,
                    event_type=f"http_{method.lower()}" if method else "http_request",
                    status=status_from_http_code(status_code),
                ),
                "ip": ip,
                "ident": None if ident == "-" else ident,
                "user": None if user == "-" else user,
                "method": method.strip() or None,
                "path": path.strip() or None,
                "protocol": protocol.strip() or None,
                "status_code": status_code,
                "bytes": 0 if bytes_str == "-" else int(bytes_str),
                "referer": None if not referer or referer == "-" else referer,
                "user_agent": user_agent or None,
            },
        })

    return {
        "format": "apache_combined",
        "fields": CORE_FIELDS + ["ip", "ident", "user", "method", "path",
                   "protocol", "status_code", "bytes", "referer", "user_agent"],
        "total_lines": len(lines),
        "entries": entries,
        "skipped_lines": skipped,
    }


def _parse_apache_date(raw: str) -> str:
    """Convert '10/Oct/2000:13:55:36 -0700' → ISO 8601 string."""
    try:
        # e.g. "10/Oct/2000:13:55:36 -0700"
        part, tz = raw.split(" ")
        day, mon, rest = part.split("/")
        year, hour, minute, second = rest.split(":", 1)[0], *rest.split(":", 1)[1].split(":")
        dt = datetime(
            int(year), _MONTHS.get(mon, 1), int(day),
            int(hour), int(minute), int(second),
        )
        return dt.isoformat() + "Z"
    except Exception:
        return raw
