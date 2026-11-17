"""ArcSight Common Event Format (CEF).

    CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension

The header is pipe-delimited (``\\|`` escapes a literal pipe); the extension
is space-separated ``key=value`` pairs whose values may contain spaces. CEF
normally travels inside a syslog line, so anything before ``CEF:`` is read as
a syslog header and supplies the host and a fallback timestamp.
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
    parse_space_separated_attributes,
    severity_from_scale,
    split_escaped,
    timestamp_from_siem,
    unescape,
)

CEF_MARKER = re.compile(r"CEF:\d+\|")

_LABEL_SUFFIX = "Label"
_EXTRA_FIELDS = [
    "hostname", "process", "message", "severity", "dest_ip", "destination_port",
    "source_port", "protocol", "file_path", "bytes_in", "bytes_out", "action",
    "url", "domain", "cef", "key_values",
]


def looks_like_cef(lines: list[str]) -> bool:
    return any(CEF_MARKER.search(line) for line in lines[:5])


def _labelled(extension: dict[str, str]) -> dict[str, str]:
    """Resolve custom fields: ``cs1Label=Rule cs1=block-ssh`` -> {"Rule": "block-ssh"}."""

    labelled: dict[str, str] = {}
    for key, label in extension.items():
        if not key.endswith(_LABEL_SUFFIX) or not label:
            continue
        value = extension.get(key[: -len(_LABEL_SUFFIX)])
        if value not in (None, ""):
            labelled[label] = value
    return labelled


def parse_cef_log(content: str, lines: list[str]) -> dict:
    entries = []
    skipped = []

    for idx, line in enumerate(lines):
        if COMMENT_LINE.match(line):
            skipped.append({"line_number": idx + 1, "reason": "comment", "raw": line})
            continue
        marker = CEF_MARKER.search(line)
        if not marker:
            skipped.append({"line_number": idx + 1, "reason": "Not a CEF record", "raw": line})
            continue

        header = split_escaped(line[marker.start() + len("CEF:"):], "|", 7)
        if len(header) < 7:
            skipped.append({"line_number": idx + 1, "reason": "Incomplete CEF header", "raw": line})
            continue
        version, vendor, product, device_version, signature_id, name, severity = (
            unescape(part.strip()) for part in header[:7]
        )
        extension = parse_space_separated_attributes(header[7]) if len(header) > 7 else {}
        carrier = carrier_fields(line[: marker.start()])

        message = first_present(extension, "msg") or name
        category = first_present(extension, "cat") or ""
        action = first_present(extension, "act")
        description = " ".join(part for part in (name, category, action or "", message) if part)
        event_type = event_type_from_text(description)

        # For a sign-in the account being authenticated is the destination
        # user; otherwise the acting (source) user is the one of interest.
        if event_type == "login_attempt":
            username = first_present(extension, "duser", "suser")
        else:
            username = first_present(extension, "suser", "duser")

        bytes_in = first_present(extension, "in")
        bytes_out = first_present(extension, "out")

        entries.append({
            "line_number": idx + 1,
            "raw": line,
            "parsed": {
                **normalize_entry(
                    timestamp=timestamp_from_siem(first_present(extension, "rt", "end", "start"))
                    or carrier.get("timestamp"),
                    ip_address=first_present(extension, "src"),
                    username=username,
                    event_type=event_type,
                    status=first_present(extension, "outcome") or status_from_text(description),
                ),
                "hostname": first_present(extension, "dvchost", "dhost", "shost") or carrier.get("hostname"),
                "process": first_present(extension, "dproc", "sproc"),
                "message": message,
                "severity": severity_from_scale(severity) or carrier.get("severity"),
                "dest_ip": first_present(extension, "dst"),
                "destination_port": first_present(extension, "dpt"),
                "source_port": first_present(extension, "spt"),
                "protocol": first_present(extension, "proto"),
                "file_path": first_present(extension, "filePath", "fname"),
                "bytes_in": bytes_in,
                "bytes_out": bytes_out,
                "action": action,
                "url": first_present(extension, "request"),
                "domain": first_present(extension, "destinationDnsDomain"),
                "cef": {
                    "version": version,
                    "device_vendor": vendor,
                    "device_product": product,
                    "device_version": device_version,
                    "signature_id": signature_id,
                    "name": name,
                    "severity": severity,
                    "labels": _labelled(extension),
                },
                "key_values": extension,
            },
        })

    return {
        "format": "cef",
        "fields": CORE_FIELDS + _EXTRA_FIELDS,
        "total_lines": len(lines),
        "entries": entries,
        "skipped_lines": skipped,
    }
