from __future__ import annotations

import re
from collections import defaultdict
from datetime import datetime
from typing import Any

from app.detection._ts import parse_ts, ts_to_str
from app.detection.models import Alert, LogRecord
from app.detection.rules.base import BaseRule

# The only LogRecord attributes a custom rule may read. Anything else the
# frontend might offer (bytes_out, host, dest_ip, ...) has no backing column
# in the parsed event schema and can never match, so field validation rejects
# it before a rule is ever saved.
STRING_FIELDS = frozenset({"event_type", "status", "ip_address", "username"})
NUMBER_FIELDS = frozenset({"port"})
TIMESTAMP_FIELDS = frozenset({"timestamp"})
KNOWN_FIELDS = STRING_FIELDS | NUMBER_FIELDS | TIMESTAMP_FIELDS

OPERATORS_BY_TYPE = {
    "string": ("equals", "not equals", "contains", "in"),
    "number": ("equals", ">", "<", "in"),
    "timestamp": ("between", "before", "after"),
}

GROUP_FIELDS = frozenset({"ip_address", "username"})

_HOUR_RANGE_RE = re.compile(r"^\s*(\d{1,2}):\d{2}\s*[–-]\s*(\d{1,2}):\d{2}\s*$")


def field_type(field: str) -> str:
    if field in NUMBER_FIELDS:
        return "number"
    if field in TIMESTAMP_FIELDS:
        return "timestamp"
    return "string"


def _match_string(actual: Any, operator: str, expected: str) -> bool:
    if actual is None:
        return False
    actual_l = str(actual).strip().lower()
    expected_l = expected.strip().lower()
    if operator == "equals":
        return actual_l == expected_l
    if operator == "not equals":
        return actual_l != expected_l
    if operator == "contains":
        return expected_l in actual_l
    if operator == "in":
        options = {item.strip().lower() for item in expected.split(",") if item.strip()}
        return actual_l in options
    return False


def _match_number(actual: Any, operator: str, expected: str) -> bool:
    if actual is None:
        return False
    try:
        if operator == "in":
            options = {int(item.strip()) for item in expected.split(",") if item.strip()}
            return int(actual) in options
        target = float(expected)
        actual_value = float(actual)
    except (TypeError, ValueError):
        return False
    if operator == "equals":
        return actual_value == target
    if operator == ">":
        return actual_value > target
    if operator == "<":
        return actual_value < target
    return False


def _parse_hour_range(value: str) -> tuple[int, int] | None:
    match = _HOUR_RANGE_RE.match(value or "")
    if not match:
        return None
    return int(match.group(1)), int(match.group(2))


def _match_timestamp(actual: Any, operator: str, expected: str) -> bool:
    dt = parse_ts(actual)
    if dt is None:
        return False
    if operator == "between":
        hour_range = _parse_hour_range(expected)
        if hour_range is None:
            return False
        start, end = hour_range
        hour = dt.hour
        if start <= end:
            return start <= hour < end
        return hour >= start or hour < end
    if operator in ("before", "after"):
        boundary = parse_ts(expected)
        if boundary is None:
            return False
        return dt < boundary if operator == "before" else dt > boundary
    return False


def evaluate_condition(record: LogRecord, condition: dict) -> bool:
    """Return True when one WHERE/AND condition matches a parsed log record."""

    field = condition.get("field")
    operator = condition.get("operator")
    value = str(condition.get("value", ""))
    actual = getattr(record, field, None) if field in KNOWN_FIELDS else None

    kind = field_type(field)
    if kind == "number":
        return _match_number(actual, operator, value)
    if kind == "timestamp":
        return _match_timestamp(actual, operator, value)
    return _match_string(actual, operator, value)


class CustomConditionRule(BaseRule):
    """
    Evaluates one persisted, user-authored condition set against parsed log
    records. All conditions must match (logical AND, mirroring the "WHERE /
    AND" rows in the Rule Builder UI). Matches are grouped by an optional
    field and bucketed into non-overlapping windows, one alert per bucket.
    """

    def __init__(
        self,
        *,
        rule_id: str,
        display_name: str,
        severity: str,
        conditions: list[dict],
        group_by: str | None = None,
        window_seconds: int = 600,
    ):
        self.rule_id = rule_id
        self.name = rule_id
        self.display_name = display_name
        self.description = f'Custom rule {rule_id} "{display_name}"'
        self.severity = severity.upper()
        self.conditions = list(conditions)
        self.group_by = group_by if group_by in GROUP_FIELDS else None
        self.window_seconds = max(60, int(window_seconds or 600))

    def _matches(self, record: LogRecord) -> bool:
        return all(evaluate_condition(record, condition) for condition in self.conditions)

    def matches(self, records: list[LogRecord]) -> list[LogRecord]:
        """Expose raw matches (used by the rule-test endpoint's dry run)."""

        return [record for record in records if self._matches(record)]

    def analyze(self, records: list[LogRecord], db=None) -> list[Alert]:
        matched = self.matches(records)
        if not matched:
            return []

        groups: dict[str, list[LogRecord]] = defaultdict(list)
        for record in matched:
            key = getattr(record, self.group_by, None) if self.group_by else None
            groups[key or "_all"].append(record)

        alerts: list[Alert] = []
        for group_key, group_records in groups.items():
            timed = sorted(
                ((record, parse_ts(record.timestamp)) for record in group_records),
                key=lambda item: (item[1] is None, item[1]),
            )

            bucket: list[tuple[LogRecord, datetime | None]] = []
            for record, ts in timed:
                if (
                    bucket
                    and ts is not None
                    and bucket[-1][1] is not None
                    and (ts - bucket[-1][1]).total_seconds() > self.window_seconds
                ):
                    alerts.append(self._alert_for_bucket(bucket, group_key))
                    bucket = []
                bucket.append((record, ts))
            if bucket:
                alerts.append(self._alert_for_bucket(bucket, group_key))

        return alerts

    def _alert_for_bucket(
        self,
        bucket: list[tuple[LogRecord, datetime | None]],
        group_key: str,
    ) -> Alert:
        bucket_records = [record for record, _ in bucket]
        timestamps = [ts for _, ts in bucket if ts is not None]
        first_seen = ts_to_str(min(timestamps)) if timestamps else None
        last_seen = ts_to_str(max(timestamps)) if timestamps else None
        source_ip = next((r.ip_address for r in bucket_records if r.ip_address), None)
        username = next((r.username for r in bucket_records if r.username), None)

        grouped_note = (
            f" grouped by {self.group_by}={group_key}" if self.group_by else ""
        )

        return Alert(
            rule=self.rule_id,
            severity=self.severity,
            source_ip=source_ip,
            username=username,
            count=len(bucket_records),
            time_window_seconds=self.window_seconds,
            first_seen=first_seen,
            last_seen=last_seen,
            description=(
                f'Custom rule {self.rule_id} "{self.display_name}" matched '
                f"{len(bucket_records)} event(s){grouped_note} "
                f"within {self.window_seconds}s."
            ),
            matched_line_numbers=[record.line_number for record in bucket_records],
        )
