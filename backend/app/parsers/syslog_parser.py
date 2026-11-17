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

# RFC 3164 (BSD syslog): Jan 10 08:00:01 server01 sshd[1234]: message
_SYSLOG_RE = re.compile(
    r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^\[:\s]+)(?:\[(\d+)\])?:\s+(.*)$'
)

# Both syslog RFCs allow a leading priority: <PRI> = facility * 8 + severity.
_PRI_RE = re.compile(r"^<(\d{1,3})>")
_MAX_PRI = 191  # facility 23, severity 7

# RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD [MSG]
#   <34>1 2026-01-10T08:00:01.003Z server01 sshd 1234 ID47 - message
_RFC5424_HEADER_RE = re.compile(r"^(\d{1,2}) (\S+) (\S+) (\S+) (\S+) (\S+) ")
_BSD_PREFIX_RE = re.compile(r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)")
_NIL = "-"
_SD_CORE_KEYS = {
    "ip_address": ("src", "src_ip", "source_ip", "ip"),
    "username": ("user", "username", "usrName"),
}

# Syslog severities 0-7 (emerg, alert, crit, err, warning, notice, info,
# debug) in this parser's existing vocabulary.
_SEVERITY_BY_CODE = ("CRITICAL", "CRITICAL", "CRITICAL", "ERROR", "WARNING", "INFO", "INFO", "DEBUG")
_SEVERITY_RANK = {"CRITICAL": 5, "ERROR": 4, "WARNING": 3, "INFO": 2, "DEBUG": 1, "UNKNOWN": 0}

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

    saw_rfc5424 = False

    for idx, line in enumerate(lines):
        if line.startswith("#"):
            continue
        pri, body = _split_pri(line)
        sd_fields: dict = {}
        rfc5424 = _RFC5424_HEADER_RE.match(body) if pri is not None else None
        if rfc5424:
            _version, ts_raw, hostname, process, pid, msgid = rfc5424.groups()
            structured_data, message = _split_structured_data(body[rfc5424.end():])
            if structured_data is None:
                skipped.append({"line_number": idx + 1, "reason": "Malformed structured data", "raw": line})
                continue
            saw_rfc5424 = True
            timestamp = None if ts_raw == _NIL else ts_raw
            hostname = None if hostname == _NIL else hostname
            process = "" if process == _NIL else process
            pid = pid if pid.isdigit() else None
            sd_fields = {"msgid": None if msgid == _NIL else msgid}
            if structured_data:
                sd_fields["structured_data"] = structured_data
                # Flattened too, so field aliases reach SD parameters.
                sd_fields["key_values"] = {
                    name: value
                    for params in structured_data.values()
                    for name, value in params.items()
                }
        else:
            m = _SYSLOG_RE.match(body)
            if not m:
                skipped.append({"line_number": idx + 1, "reason": "No regex match", "raw": line})
                continue
            ts_raw, hostname, process, pid, message = m.groups()
            timestamp = _normalize_date(ts_raw)

        process = process.strip()
        message = message.strip()

        structured = extract_from_message(process, message)
        core = {
            "timestamp": timestamp,
            "ip_address": first_ip(message),
            "username": username_from_text(message),
            "event_type": event_type_from_text(message),
            "status": status_from_text(message),
        }
        # Structured-data parameters state the source and account outright,
        # which beats guessing them from the free-text message.
        for key, names in _SD_CORE_KEYS.items():
            stated = next(
                (sd_fields["key_values"][name] for name in names if sd_fields.get("key_values", {}).get(name)),
                None,
            )
            if stated:
                core[key] = stated
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
                "severity": _severity(pri, message),
                **_pri_fields(pri),
                **sd_fields,
                **extra,
            },
        })

    return {
        "format": "syslog_rfc5424" if saw_rfc5424 else "syslog",
        "fields": CORE_FIELDS + ["hostname", "process", "pid", "message", "severity"],
        "total_lines": len(lines),
        "entries": entries,
        "skipped_lines": skipped,
    }


def _split_pri(line: str) -> tuple[int | None, str]:
    """Separate a leading ``<PRI>`` from the rest of the line."""

    match = _PRI_RE.match(line)
    if not match or int(match.group(1)) > _MAX_PRI:
        return None, line
    return int(match.group(1)), line[match.end():]


def _pri_fields(pri: int | None) -> dict:
    if pri is None:
        return {}
    return {"syslog_facility": pri >> 3, "syslog_severity": pri & 7}


def _severity(pri: int | None, message: str) -> str:
    """The sender's stated severity, raised when the text says more.

    sshd logs a failed password at ``auth.info``; keeping the keyword check
    means the same event reads the same whether or not a relay added a PRI.
    """

    from_text = _detect_severity(message)
    if pri is None:
        return from_text
    from_pri = _SEVERITY_BY_CODE[pri & 7]
    return max(from_pri, from_text, key=_SEVERITY_RANK.__getitem__)


def _split_structured_data(text: str) -> tuple[dict | None, str]:
    """Split RFC 5424 STRUCTURED-DATA from MSG.

    Returns ``({sd_id: {param: value}}, message)``; the dict is empty for the
    nil value and ``None`` when the structured data is malformed.
    """

    if text.startswith(_NIL):
        return {}, text[1:].lstrip(" ").lstrip("\ufeff")
    elements: dict[str, dict[str, str]] = {}
    index = 0
    while index < len(text) and text[index] == "[":
        index += 1
        start = index
        while index < len(text) and text[index] not in " ]":
            index += 1
        sd_id = text[start:index]
        if not sd_id:
            return None, ""
        params: dict[str, str] = {}
        while index < len(text) and text[index] == " ":
            index += 1
            start = index
            while index < len(text) and text[index] not in "=]":
                index += 1
            name = text[start:index]
            if text[index:index + 2] != '="':
                return None, ""
            index += 2
            value: list[str] = []
            while index < len(text) and text[index] != '"':
                # \" \\ and \] are the only escapes inside a PARAM-VALUE.
                if text[index] == "\\" and text[index + 1:index + 2] in ('"', "\\", "]"):
                    index += 1
                value.append(text[index])
                index += 1
            if index >= len(text):
                return None, ""
            index += 1
            params[name] = "".join(value)
        if index >= len(text) or text[index] != "]":
            return None, ""
        index += 1
        elements[sd_id] = params
    if not elements:
        return None, ""
    return elements, text[index:].lstrip(" ").lstrip("\ufeff")


def parse_syslog_prefix(prefix: str) -> dict:
    """Read the syslog header that precedes an embedded CEF/LEEF message.

    Returns whichever of ``timestamp``, ``hostname`` and ``severity`` the
    header states; an empty dict when it is not a syslog header at all.
    """

    pri, body = _split_pri(prefix.strip())
    fields: dict = {}
    if pri is not None:
        fields["severity"] = _SEVERITY_BY_CODE[pri & 7]
    rfc5424 = _RFC5424_HEADER_RE.match(body + " ") if pri is not None else None
    if rfc5424:
        _version, timestamp, hostname = rfc5424.groups()[:3]
        if timestamp != _NIL:
            fields["timestamp"] = timestamp
        if hostname != _NIL:
            fields["hostname"] = hostname
        return fields
    bsd = _BSD_PREFIX_RE.match(body)
    if bsd:
        fields["timestamp"] = _normalize_date(bsd.group(1))
        fields["hostname"] = bsd.group(2)
    return fields


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
