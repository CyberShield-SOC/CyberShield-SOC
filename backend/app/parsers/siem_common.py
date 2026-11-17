"""Helpers shared by the CEF and LEEF parsers.

Both formats are a pipe-delimited header followed by ``key=value``
attributes, are usually carried inside a syslog line, and use the same 0-10
severity scale and the same handful of timestamp spellings.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from app.parsers.syslog_parser import parse_syslog_prefix

# CEF/LEEF timestamps that are not epoch milliseconds. The year-less forms
# borrow the current year, as classic syslog does.
_TIME_FORMATS = (
    ("%b %d %Y %H:%M:%S.%f", False),
    ("%b %d %Y %H:%M:%S", False),
    ("%b %d %H:%M:%S.%f", True),
    ("%b %d %H:%M:%S", True),
    ("%Y-%m-%d %H:%M:%S.%f", False),
    ("%Y-%m-%d %H:%M:%S", False),
)
_TRAILING_ZONE = re.compile(r"\s+[A-Z]{2,5}$")
_NUMERIC_SEVERITY = re.compile(r"\d{1,2}")
_NAMED_SEVERITY = {
    "unknown": None,
    "low": "LOW",
    "medium": "MEDIUM",
    "high": "HIGH",
    "very-high": "CRITICAL",
    "very high": "CRITICAL",
}

# Keys start at the beginning or after whitespace and run up to an unescaped
# "=". A value then runs to the next such key, so it may contain spaces.
_SPACE_SEPARATED_KEY = re.compile(r"(?:^|(?<=\s))([A-Za-z0-9_.\[\]-]+)=")


def severity_from_scale(value) -> str | None:
    """Map the CEF/LEEF 0-10 scale (or its names) onto LOW..CRITICAL.

    Bands follow the CEF specification: 0-3 Low, 4-6 Medium, 7-8 High,
    9-10 Very-High.
    """

    text = str(value or "").strip()
    if not text:
        return None
    if _NUMERIC_SEVERITY.fullmatch(text):
        number = int(text)
        if number > 10:
            return None
        if number <= 3:
            return "LOW"
        if number <= 6:
            return "MEDIUM"
        if number <= 8:
            return "HIGH"
        return "CRITICAL"
    return _NAMED_SEVERITY.get(text.lower())


def timestamp_from_siem(value) -> str | None:
    """Normalise an ``rt``/``devTime`` value to ISO 8601 where possible.

    Epoch milliseconds and the documented text formats become UTC ISO
    strings. Anything else is returned as written so the event keeps its
    original text; an unparseable time is simply stored without a parsed
    timestamp downstream.
    """

    text = str(value or "").strip()
    if not text:
        return None
    if text.isdigit() and len(text) >= 10:
        seconds = int(text) / (1000 if len(text) >= 12 else 1)
        try:
            return datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat().replace("+00:00", "Z")
        except (OverflowError, OSError, ValueError):
            return text
    candidate = _TRAILING_ZONE.sub("", text)
    for fmt, needs_year in _TIME_FORMATS:
        try:
            if needs_year:
                parsed = datetime.strptime(f"{datetime.now().year} {candidate}", f"%Y {fmt}")
            else:
                parsed = datetime.strptime(candidate, fmt)
        except ValueError:
            continue
        return parsed.isoformat() + "Z"
    return text


def split_escaped(text: str, delimiter: str, maxsplit: int) -> list[str]:
    """Split on ``delimiter`` wherever it is not backslash-escaped."""

    parts: list[str] = []
    current: list[str] = []
    index = 0
    while index < len(text):
        char = text[index]
        if char == "\\" and index + 1 < len(text):
            current.append(text[index : index + 2])
            index += 2
            continue
        if char == delimiter and len(parts) < maxsplit:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
        index += 1
    parts.append("".join(current))
    return parts


def unescape(value: str) -> str:
    """Resolve the backslash escapes CEF and LEEF allow in values."""

    out: list[str] = []
    index = 0
    while index < len(value):
        char = value[index]
        if char == "\\" and index + 1 < len(value):
            following = value[index + 1]
            out.append({"n": "\n", "r": "\r", "t": "\t"}.get(following, following))
            index += 2
            continue
        out.append(char)
        index += 1
    return "".join(out)


def parse_space_separated_attributes(text: str) -> dict[str, str]:
    """Parse ``k1=v1 k2=value with spaces k3=v3`` into a dict."""

    keys = [
        match
        for match in _SPACE_SEPARATED_KEY.finditer(text)
        # "\=" inside a value is data, not the start of a key.
        if not (match.end() >= 2 and text[match.end() - 2] == "\\")
    ]
    attributes: dict[str, str] = {}
    for position, match in enumerate(keys):
        end = keys[position + 1].start() if position + 1 < len(keys) else len(text)
        attributes[match.group(1)] = unescape(text[match.end() : end].strip())
    return attributes


def parse_delimited_attributes(text: str, delimiter: str) -> dict[str, str]:
    """Parse LEEF attributes separated by a single delimiter character."""

    attributes: dict[str, str] = {}
    for pair in text.split(delimiter):
        key, separator, value = pair.partition("=")
        key = key.strip()
        if separator and key:
            attributes[key] = unescape(value.strip())
    return attributes


def first_present(attributes: dict[str, str], *keys: str) -> str | None:
    for key in keys:
        value = attributes.get(key)
        if value not in (None, "", "-"):
            return value
    return None


def carrier_fields(prefix: str) -> dict:
    """What the syslog line wrapping a CEF/LEEF message says about it."""

    return parse_syslog_prefix(prefix) if prefix.strip() else {}
