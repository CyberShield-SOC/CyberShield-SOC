import re
import json
from app.parsers.field_normalizer import (
    CORE_FIELDS,
    event_type_from_text,
    first_ip,
    normalize_entry,
    status_from_text,
    username_from_text,
)

_TIMESTAMP_PATTERNS = [
    re.compile(r'(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)'),
    re.compile(r'(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})'),
    re.compile(r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'),
]

_LEVEL_PATTERN = re.compile(
    r'\b(CRITICAL|FATAL|ERROR|WARN(?:ING)?|INFO|DEBUG|TRACE|NOTICE)\b', re.IGNORECASE
)

_KV_PATTERN = re.compile(r'(\w+)=(?:"([^"]*)"|([\w./:\-]+))')


def parse_generic_log(content: str, lines: list[str]) -> dict:
    entries = []

    for idx, line in enumerate(lines):
        timestamp = _extract_timestamp(line)
        key_values = _extract_kv(line)
        json_data = _extract_json(line)

        entries.append({
            "line_number": idx + 1,
            "raw": line,
            "parsed": {
                **normalize_entry(
                    timestamp=timestamp,
                    ip_address=_pick_value(key_values, json_data, "ip_address", "source_ip", "src_ip", "src", "ip") or first_ip(line),
                    username=_pick_value(key_values, json_data, "username", "user", "account") or username_from_text(line),
                    event_type=_pick_value(key_values, json_data, "event_type", "event", "action") or event_type_from_text(line),
                    status=_pick_value(key_values, json_data, "status", "result", "outcome") or status_from_text(line),
                ),
                "level": _extract_level(line),
                "key_values": key_values,
                "json": json_data,
                "message": line.strip(),
            },
        })

    return {
        "format": "generic",
        "fields": CORE_FIELDS + ["level", "key_values", "json", "message"],
        "total_lines": len(lines),
        "entries": entries,
        "skipped_lines": [],
    }


def _extract_timestamp(line: str):
    for pattern in _TIMESTAMP_PATTERNS:
        m = pattern.search(line)
        if m:
            return m.group(1)
    return None


def _extract_level(line: str):
    m = _LEVEL_PATTERN.search(line)
    return m.group(1).upper() if m else None


def _extract_kv(line: str):
    pairs = {m.group(1): m.group(2) or m.group(3) for m in _KV_PATTERN.finditer(line)}
    return pairs if pairs else None


def _extract_json(line: str):
    start = line.find("{")
    end = line.rfind("}")
    if start == -1 or end <= start:
        return None
    try:
        return json.loads(line[start:end + 1])
    except Exception:
        return None


def _pick_value(key_values, json_data, *keys):
    for source in (key_values, json_data):
        if not isinstance(source, dict):
            continue
        for key in keys:
            value = source.get(key)
            if value is not None:
                return value
    return None
