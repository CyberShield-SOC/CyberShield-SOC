import re

CORE_FIELDS = ["timestamp", "ip_address", "username", "event_type", "status"]

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def normalize_entry(
    *,
    timestamp=None,
    ip_address=None,
    username=None,
    event_type=None,
    status=None,
) -> dict:
    """
    Returns the exact Sprint 1 fields expected by the frontend table.
    Parsers can still include extra details, but these fields stay consistent.
    """
    return {
        "timestamp": timestamp,
        "ip_address": ip_address,
        "username": username,
        "event_type": event_type,
        "status": status,
    }


def first_ip(text: str):
    match = _IP_RE.search(text or "")
    return match.group(0) if match else None


def status_from_text(text: str):
    lowered = (text or "").lower()
    if any(word in lowered for word in ["failed", "failure", "invalid", "denied", "blocked", "error"]):
        return "FAILED"
    if any(word in lowered for word in ["accepted", "success", "successful", "allowed"]):
        return "SUCCESS"
    return "UNKNOWN"


def event_type_from_text(text: str):
    lowered = (text or "").lower()
    if any(word in lowered for word in ["password", "login", "authentication", "auth"]):
        return "login_attempt"
    if "port_scan" in lowered or "scan" in lowered:
        return "port_scan"
    if "dns" in lowered:
        return "dns_query"
    if "sudo" in lowered:
        return "privilege_escalation"
    return "security_event"


def username_from_text(text: str):
    text = text or ""

    patterns = [
        r"\bfor\s+(?:invalid user\s+)?([A-Za-z0-9_.-]+)\b",
        r"\buser=([A-Za-z0-9_.-]+)\b",
        r"\bUSER=([A-Za-z0-9_.-]+)\b",
        r"\b([A-Za-z0-9_.-]+)\s+:\s+TTY=",
    ]

    for pattern in patterns:
        match = re.search(pattern, text)
        if match:
            return match.group(1)

    return None


def status_from_http_code(status_code: int):
    if 200 <= status_code < 400:
        return "SUCCESS"
    if 400 <= status_code < 600:
        return "FAILED"
    return "UNKNOWN"
