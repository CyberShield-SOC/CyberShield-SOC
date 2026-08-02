from app.parsers.apache_parser import parse_apache_log
from app.parsers.syslog_parser import parse_syslog
from app.parsers.csv_parser import parse_csv_log
from app.parsers.json_parser import parse_json_log
from app.parsers.generic_parser import parse_generic_log

import csv
import re

# Apache combined: IP - user [DD/Mon/YYYY:HH:MM:SS tz] "METHOD path HTTP/x" status bytes
_APACHE_PATTERN = re.compile(r'^\S+\s+\S+\s+\S+\s+\[\d{2}/\w+/\d{4}')

# Syslog: Mon DD HH:MM:SS hostname process[pid]: message
_SYSLOG_PATTERN = re.compile(r'^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+\S+')

# Delimiters the CSV parser can safely take on when a .txt file turns out to
# be a delimiter-separated export rather than free-form log lines.
_DELIMITER_CANDIDATES = ",\t;|"


def _sniff_delimiter(lines: list[str]) -> str | None:
    """
    Best-effort detection of a delimiter-separated header in .txt content.

    Returns the detected delimiter only when the sample both looks
    delimited and appears to start with a header row, so free-form text
    (syslog/apache/generic) is never misrouted into the CSV parser and
    silently mangled into incorrect fields. Any ambiguity is treated as
    "not delimited" and falls back to the existing content-pattern
    detection below.
    """
    sample = "\n".join(lines[:20])
    if not sample.strip():
        return None
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=_DELIMITER_CANDIDATES)
        if not csv.Sniffer().has_header(sample):
            return None
    except csv.Error:
        return None
    return dialect.delimiter


def parse_log(content: str, filename: str) -> dict:
    """
    Auto-detects log format from filename extension and content patterns,
    then delegates to the appropriate parser.

    Returns a dict with keys:
        format, fields, total_lines, entries, skipped_lines
    """
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    lines = [l for l in content.splitlines() if l.strip()]

    if ext == "csv":
        return parse_csv_log(content, lines)

    if ext in {"json", "jsonl"}:
        return parse_json_log(content, lines)

    if ext == "txt":
        delimiter = _sniff_delimiter(lines)
        if delimiter:
            return parse_csv_log(content, lines, delimiter=delimiter)
        # Falls through to the same syslog/apache/generic detection used
        # for .log files below, since plain-text log lines and .log files
        # are structurally the same thing.

    # Check content patterns on first 5 lines
    sample = lines[:5]
    if any(_APACHE_PATTERN.match(l) for l in sample):
        return parse_apache_log(content, lines)

    if any(_SYSLOG_PATTERN.match(l) for l in sample):
        return parse_syslog(content, lines)

    return parse_generic_log(content, lines)
