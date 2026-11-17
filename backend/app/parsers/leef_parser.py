"""IBM QRadar Log Event Extended Format (LEEF).

    LEEF:1.0|Vendor|Product|Version|EventID|key=value<TAB>key=value
    LEEF:2.0|Vendor|Product|Version|EventID|Delimiter|key=value<D>key=value

LEEF 1.0 attributes are tab-separated. LEEF 2.0 adds an optional header
field naming the delimiter, as a character (``^``) or a hex code (``0x09``).
Some senders flatten the tabs to spaces; when no delimiter is found the
attributes are read as space-separated pairs instead of being dropped.
"""

from __future__ import annotations

import re

from app.parsers.field_normalizer import (
    COMMENT_LINE,
    CORE_FIELDS,
    event_type_from_text,
    normalize_entry,
    status_from_text,
)
from app.parsers.siem_common import (
    carrier_fields,
    first_present,
    parse_delimited_attributes,
    parse_space_separated_attributes,
    severity_from_scale,
    split_escaped,
    timestamp_from_siem,
    unescape,
)

LEEF_MARKER = re.compile(r"LEEF:(1\.0|2\.0|1|2)\|")

_HEX_DELIMITER = re.compile(r"(?:0x|x)([0-9A-Fa-f]{2,4})")
_EXTRA_FIELDS = [
    "hostname", "message", "severity", "dest_ip", "destination_port", "source_port",
    "protocol", "bytes_in", "bytes_out", "action", "url", "domain", "leef", "key_values",
]


def looks_like_leef(lines: list[str]) -> bool:
    return any(LEEF_MARKER.search(line) for line in lines[:5])


def _delimiter(field: str) -> str | None:
    """The LEEF 2.0 delimiter field as a single character, if it is one."""

    hex_code = _HEX_DELIMITER.fullmatch(field)
    if hex_code:
        return chr(int(hex_code.group(1), 16))
    return field if len(field) == 1 else None


def _attributes(version: str, tail: str) -> dict[str, str]:
    delimiter = "\t"
    if version.startswith("2"):
        # The delimiter field is optional: without it the attributes start
        # straight after the event id, exactly as in LEEF 1.0.
        candidate, separator, remainder = tail.partition("|")
        declared = _delimiter(candidate) if separator else None
        if declared is not None:
            delimiter, tail = declared, remainder
    if delimiter in tail:
        return parse_delimited_attributes(tail, delimiter)
    return parse_space_separated_attributes(tail)


def parse_leef_log(content: str, lines: list[str]) -> dict:
    entries = []
    skipped = []

    for idx, line in enumerate(lines):
        if COMMENT_LINE.match(line):
            skipped.append({"line_number": idx + 1, "reason": "comment", "raw": line})
            continue
        marker = LEEF_MARKER.search(line)
        if not marker:
            skipped.append({"line_number": idx + 1, "reason": "Not a LEEF record", "raw": line})
            continue

        header = split_escaped(line[marker.start() + len("LEEF:"):], "|", 5)
        if len(header) < 5:
            skipped.append({"line_number": idx + 1, "reason": "Incomplete LEEF header", "raw": line})
            continue
        version, vendor, product, product_version, event_id = (
            unescape(part.strip()) for part in header[:5]
        )
        attributes = _attributes(version, header[5]) if len(header) > 5 else {}
        carrier = carrier_fields(line[: marker.start()])

        category = first_present(attributes, "cat") or ""
        action = first_present(attributes, "action", "act")
        message = first_present(attributes, "msg", "message") or event_id
        description = " ".join(part for part in (event_id, category, action or "", message) if part)

        entries.append({
            "line_number": idx + 1,
            "raw": line,
            "parsed": {
                **normalize_entry(
                    timestamp=timestamp_from_siem(first_present(attributes, "devTime"))
                    or carrier.get("timestamp"),
                    ip_address=first_present(attributes, "src"),
                    username=first_present(attributes, "usrName", "accountName"),
                    event_type=event_type_from_text(description),
                    status=first_present(attributes, "outcome", "result") or status_from_text(description),
                ),
                "hostname": first_present(attributes, "identHostName", "dvchost") or carrier.get("hostname"),
                "message": message,
                "severity": severity_from_scale(first_present(attributes, "sev")) or carrier.get("severity"),
                "dest_ip": first_present(attributes, "dst"),
                "destination_port": first_present(attributes, "dstPort"),
                "source_port": first_present(attributes, "srcPort"),
                "protocol": first_present(attributes, "proto"),
                # LEEF counts bytes from each end of the conversation: what
                # the source sent is what left the monitored host.
                "bytes_out": first_present(attributes, "srcBytes"),
                "bytes_in": first_present(attributes, "dstBytes"),
                "action": action,
                "url": first_present(attributes, "url"),
                "domain": first_present(attributes, "domain"),
                "leef": {
                    "version": version,
                    "vendor": vendor,
                    "product": product,
                    "product_version": product_version,
                    "event_id": event_id,
                },
                "key_values": attributes,
            },
        })

    return {
        "format": "leef",
        "fields": CORE_FIELDS + _EXTRA_FIELDS,
        "total_lines": len(lines),
        "entries": entries,
        "skipped_lines": skipped,
    }
