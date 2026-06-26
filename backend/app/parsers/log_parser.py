from app.parsers.apache_parser import parse_apache_log
from app.parsers.syslog_parser import parse_syslog
from app.parsers.csv_parser import parse_csv_log
from app.parsers.generic_parser import parse_generic_log

import re

# Apache combined: IP - user [DD/Mon/YYYY:HH:MM:SS tz] "METHOD path HTTP/x" status bytes
_APACHE_PATTERN = re.compile(r'^\S+\s+\S+\s+\S+\s+\[\d{2}/\w+/\d{4}')

# Syslog: Mon DD HH:MM:SS hostname process[pid]: message
_SYSLOG_PATTERN = re.compile(r'^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+\S+')


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

    # Check content patterns on first 5 lines
    sample = lines[:5]
    if any(_APACHE_PATTERN.match(l) for l in sample):
        return parse_apache_log(content, lines)

    if any(_SYSLOG_PATTERN.match(l) for l in sample):
        return parse_syslog(content, lines)

    return parse_generic_log(content, lines)
