import re

CORE_FIELDS = ["timestamp", "ip_address", "username", "event_type", "status"]

_IP_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
_IP_RE = re.compile(rf"\b(?:{_IP_OCTET}\.){{3}}{_IP_OCTET}\b")

_FAILED_WORDS = ("failed", "failure", "invalid", "denied", "blocked", "error", "reject", "rejected")
_SUCCESS_WORDS = ("accepted", "success", "successful", "allowed", "pass", "passed", "ok")
_INFO_WORDS = ("closed", "disconnected", "started", "stopped", "info")

_STATUS_ALIASES = {
    "fail": "FAILED",
    "failed": "FAILED",
    "failure": "FAILED",
    "denied": "FAILED",
    "blocked": "FAILED",
    "rejected": "FAILED",
    "error": "FAILED",
    "success": "SUCCESS",
    "successful": "SUCCESS",
    "accepted": "SUCCESS",
    "allowed": "SUCCESS",
    "pass": "SUCCESS",
    "passed": "SUCCESS",
    "ok": "SUCCESS",
    "info": "INFO",
    "closed": "INFO",
    "disconnected": "INFO",
    "unknown": "UNKNOWN",
}


def normalize_entry(
    *,
    timestamp=None,
    ip_address=None,
    username=None,
    event_type=None,
    status=None,
) -> dict:
    return {
        "timestamp": _clean_text(timestamp),
        "ip_address": normalize_ip(ip_address),
        "username": _clean_text(username),
        "event_type": normalize_event_type(event_type),
        "status": normalize_status(status),
    }


def first_ip(text: str):
    match = _IP_RE.search(text or "")
    return match.group(0) if match else None


def normalize_ip(value):
    value = _clean_text(value)
    if not value:
        return None
    match = _IP_RE.fullmatch(value)
    return value if match else None


def normalize_status(value):
    value = _clean_text(value)
    if not value:
        return "UNKNOWN"

    key = re.sub(r"[\s_-]+", " ", value).strip().lower()
    return _STATUS_ALIASES.get(key, key.upper())


def normalize_event_type(value):
    value = _clean_text(value)
    if not value:
        return "security_event"
    normalized = re.sub(r"[^a-zA-Z0-9]+", "_", value).strip("_").lower()
    return normalized or "security_event"


def status_from_text(text: str):
    lowered = (text or "").lower()
    if any(word in lowered for word in _FAILED_WORDS):
        return "FAILED"
    if any(word in lowered for word in _SUCCESS_WORDS):
        return "SUCCESS"
    if any(word in lowered for word in _INFO_WORDS):
        return "INFO"
    return "UNKNOWN"


def event_type_from_text(text: str):
    lowered = (text or "").lower()
    # sudo must be checked before auth keywords — "sudo auth failure" would
    # otherwise match "auth" and be misclassified as login_attempt
    if "sudo" in lowered:
        return "privilege_escalation"
    if "connection closed" in lowered or "disconnected" in lowered:
        return "connection_closed"
    if any(word in lowered for word in ["password", "login", "authentication", "auth", "invalid user"]):
        return "login_attempt"
    if "port_scan" in lowered or "scan" in lowered:
        return "port_scan"
    if "dns" in lowered:
        return "dns_query"
    return "security_event"


def username_from_text(text: str):
    text = text or ""
    patterns = [
        r"\bfor\s+(?:invalid user\s+)?([A-Za-z0-9_.-]+)\b",
<<<<<<< HEAD
        r"\bfrom\s+user\s+([A-Za-z0-9_.-]+)\b",
=======
        r"\binvalid user\s+([A-Za-z0-9_.-]+)\b",
>>>>>>> ff90b3c (fix(detection): match Invalid-user syslog lines and drop broken sample dir)
        r"\buser=([A-Za-z0-9_.-]+)\b",
        r"\bUSER=([A-Za-z0-9_.-]+)\b",
        r"\buser:\s*([A-Za-z0-9_.-]+)\b",
        r"\busername[:=]\s*([A-Za-z0-9_.-]+)\b",
        r"\b([A-Za-z0-9_.-]+)\s+:\s+TTY=",
        r"\blogname=([A-Za-z0-9_.-]+)\b",
    ]
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return match.group(1)
    return None


def status_from_http_code(status_code: int):
    if 200 <= status_code < 400:
        return "SUCCESS"
    if 400 <= status_code < 600:
        return "FAILED"
    return "UNKNOWN"


def _clean_text(value):
    if value is None:
        return None
    value = str(value).strip()
    return None if value in ("", "-", "null", "NULL", "None") else value
