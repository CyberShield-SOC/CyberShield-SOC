import csv
import io
from app.parsers.field_normalizer import CORE_FIELDS, first_ip, normalize_entry


def parse_csv_log(content: str, lines: list[str]) -> dict:
    entries = []
    skipped = []

    reader = csv.DictReader(io.StringIO(content))

    if not reader.fieldnames:
        return {
            "format": "csv",
            "fields": [],
            "total_lines": len(lines),
            "entries": [],
            "skipped_lines": [{"line_number": 1, "reason": "No header row found", "raw": ""}],
        }

    fields = [f.strip().lower().replace(" ", "_") for f in reader.fieldnames]

    for idx, row in enumerate(reader):
        line_number = idx + 2  # offset for header row
        try:
            row_data = {
                fields[i]: _coerce(v)
                for i, (k, v) in enumerate(row.items())
                if i < len(fields)
            }
            parsed = {
                **normalize_entry(
                    timestamp=_pick(row_data, "timestamp", "time", "date"),
                    ip_address=_pick(row_data, "ip_address", "source_ip", "src_ip", "ip", "client_ip") or first_ip(str(row_data)),
                    username=_pick(row_data, "username", "user", "account"),
                    event_type=_pick(row_data, "event_type", "event", "action", "activity"),
                    status=_pick(row_data, "status", "result", "outcome"),
                ),
                **row_data,
            }
            raw_line = lines[line_number - 1] if line_number - 1 < len(lines) else ""
            entries.append({"line_number": line_number, "raw": raw_line, "parsed": parsed})
        except Exception as e:
            raw_line = lines[line_number - 1] if line_number - 1 < len(lines) else ""
            skipped.append({"line_number": line_number, "reason": str(e), "raw": raw_line})

    return {
        "format": "csv",
        "fields": list(dict.fromkeys(CORE_FIELDS + fields)),
        "total_lines": len(lines),
        "entries": entries,
        "skipped_lines": skipped,
    }


def _coerce(value: str):
    """Convert string values to their natural Python types."""
    if value is None or value.strip() in ("", "-", "null", "NULL", "None"):
        return None
    v = value.strip()
    try:
        return int(v)
    except ValueError:
        pass
    try:
        return float(v)
    except ValueError:
        pass
    if v.lower() == "true":
        return True
    if v.lower() == "false":
        return False
    return v


def _pick(data: dict, *keys):
    for key in keys:
        value = data.get(key)
        if value is not None:
            return value
    return None
