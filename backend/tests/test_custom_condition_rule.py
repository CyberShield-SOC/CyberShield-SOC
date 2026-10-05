"""Unit coverage for the user-authored custom rule evaluator: condition
matching per field type, grouping, and window bucketing.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

pytestmark = pytest.mark.no_db

from app.detection.models import LogRecord
from app.detection.rules.custom_condition import CustomConditionRule, evaluate_condition

_BASE = datetime(2026, 6, 14, 2, 0, 0, tzinfo=timezone.utc)


def _ts(delta_s: int) -> str:
    return (_BASE + timedelta(seconds=delta_s)).strftime("%Y-%m-%dT%H:%M:%SZ")


def rec(n, ts=None, ip=None, user=None, event="login_attempt", status="FAILED", port=None) -> LogRecord:
    return LogRecord(
        line_number=n,
        timestamp=ts,
        ip_address=ip,
        username=user,
        event_type=event,
        status=status,
        port=port,
    )


# ── Field-type condition matching ───────────────────────────────────────────

def test_string_equals_is_case_insensitive():
    condition = {"field": "event_type", "operator": "equals", "value": "Login_Attempt"}
    assert evaluate_condition(rec(1, event="login_attempt"), condition) is True


def test_string_not_equals():
    condition = {"field": "status", "operator": "not equals", "value": "SUCCESS"}
    assert evaluate_condition(rec(1, status="FAILED"), condition) is True
    assert evaluate_condition(rec(1, status="SUCCESS"), condition) is False


def test_string_contains():
    condition = {"field": "username", "operator": "contains", "value": "adm"}
    assert evaluate_condition(rec(1, user="admin"), condition) is True
    assert evaluate_condition(rec(1, user="root"), condition) is False


def test_string_in_list():
    condition = {"field": "ip_address", "operator": "in", "value": "10.0.0.1, 10.0.0.2"}
    assert evaluate_condition(rec(1, ip="10.0.0.2"), condition) is True
    assert evaluate_condition(rec(1, ip="10.0.0.3"), condition) is False


def test_number_operators():
    assert evaluate_condition(rec(1, port=22), {"field": "port", "operator": "equals", "value": "22"}) is True
    assert evaluate_condition(rec(1, port=4444), {"field": "port", "operator": ">", "value": "1024"}) is True
    assert evaluate_condition(rec(1, port=80), {"field": "port", "operator": "<", "value": "1024"}) is True
    assert evaluate_condition(rec(1, port=443), {"field": "port", "operator": "in", "value": "80, 443"}) is True


def test_number_field_missing_never_matches():
    assert evaluate_condition(rec(1, port=None), {"field": "port", "operator": "equals", "value": "22"}) is False


def test_timestamp_between_hour_range():
    condition = {"field": "timestamp", "operator": "between", "value": "00:00 – 06:00"}
    assert evaluate_condition(rec(1, ts="2026-06-14T02:30:00Z"), condition) is True
    assert evaluate_condition(rec(1, ts="2026-06-14T12:00:00Z"), condition) is False


def test_timestamp_between_wraps_midnight():
    condition = {"field": "timestamp", "operator": "between", "value": "22:00-06:00"}
    assert evaluate_condition(rec(1, ts="2026-06-14T23:00:00Z"), condition) is True
    assert evaluate_condition(rec(1, ts="2026-06-14T12:00:00Z"), condition) is False


def test_timestamp_before_and_after():
    before = {"field": "timestamp", "operator": "before", "value": "2026-06-14T02:00:00Z"}
    after = {"field": "timestamp", "operator": "after", "value": "2026-06-14T02:00:00Z"}
    assert evaluate_condition(rec(1, ts="2026-06-14T01:00:00Z"), before) is True
    assert evaluate_condition(rec(1, ts="2026-06-14T03:00:00Z"), after) is True


# ── Timezone-aware hour-of-day conditions ───────────────────────────────────
#
# America/Chicago is UTC-5 in June (CDT) and UTC-6 in January (CST), so the
# same UTC hour lands on different local hours in the two seasons. The
# summer/winter pair below is what proves the zone is applied per event
# rather than as a fixed offset.

_CHICAGO_OFF_HOURS = {"field": "timestamp", "operator": "between", "value": "00:00 – 06:00", "timezone": "America/Chicago"}


def test_local_window_matches_summer_events_under_cdt():
    # 05:30Z on 14 June is 00:30 CDT, inside the local 00:00–06:00 window.
    assert evaluate_condition(rec(1, ts="2026-06-14T05:30:00Z"), _CHICAGO_OFF_HOURS) is True
    # 10:59Z is 05:59 CDT, still inside the window.
    assert evaluate_condition(rec(1, ts="2026-06-14T10:59:00Z"), _CHICAGO_OFF_HOURS) is True
    # The end is exclusive: 11:00Z is exactly 06:00 CDT.
    assert evaluate_condition(rec(1, ts="2026-06-14T11:00:00Z"), _CHICAGO_OFF_HOURS) is False
    # 12:00Z is 07:00 CDT, outside the window.
    assert evaluate_condition(rec(1, ts="2026-06-14T12:00:00Z"), _CHICAGO_OFF_HOURS) is False


def test_local_window_matches_winter_events_under_cst():
    # 05:30Z on 14 January is 23:30 CST the previous day, outside the window.
    # A fixed UTC-5 offset would wrongly put it at 00:30 and match.
    assert evaluate_condition(rec(1, ts="2026-01-14T05:30:00Z"), _CHICAGO_OFF_HOURS) is False
    # 06:30Z is 00:30 CST, inside the window.
    assert evaluate_condition(rec(1, ts="2026-01-14T06:30:00Z"), _CHICAGO_OFF_HOURS) is True
    # 11:59Z is 05:59 CST, still inside; 12:00Z is 06:00 CST, outside.
    assert evaluate_condition(rec(1, ts="2026-01-14T11:59:00Z"), _CHICAGO_OFF_HOURS) is True
    assert evaluate_condition(rec(1, ts="2026-01-14T12:00:00Z"), _CHICAGO_OFF_HOURS) is False


def test_no_timezone_keeps_utc_behaviour():
    no_zone = {"field": "timestamp", "operator": "between", "value": "00:00 – 06:00"}
    utc_zone = {**no_zone, "timezone": "UTC"}
    # The same event, 05:30Z: inside the UTC window, whether or not "UTC" is named.
    for condition in (no_zone, utc_zone):
        assert evaluate_condition(rec(1, ts="2026-06-14T05:30:00Z"), condition) is True
        assert evaluate_condition(rec(1, ts="2026-01-14T05:30:00Z"), condition) is True
    # A condition saved before the timezone field existed has no "timezone" key at all.
    assert "timezone" not in no_zone
    assert evaluate_condition(rec(1, ts="2026-06-14T12:00:00Z"), no_zone) is False


def test_naive_timestamp_is_treated_as_utc():
    # parse_ts can return a naive datetime; it must be read as UTC, not local time.
    assert evaluate_condition(rec(1, ts="2026-06-14T05:30:00"), _CHICAGO_OFF_HOURS) is True


def test_unknown_timezone_at_runtime_never_matches():
    bad = {**_CHICAGO_OFF_HOURS, "timezone": "Mars/Olympus"}
    assert evaluate_condition(rec(1, ts="2026-06-14T05:30:00Z"), bad) is False


def test_local_window_in_rule_bucketing_keeps_only_local_off_hours_events():
    rule = CustomConditionRule(
        rule_id="R-TZ",
        display_name="Off-hours failed logins (Chicago)",
        severity="high",
        conditions=[
            {"field": "status", "operator": "equals", "value": "FAILED"},
            _CHICAGO_OFF_HOURS,
        ],
        group_by="ip_address",
        window_seconds=600,
    )
    records = [
        rec(1, ts="2026-06-14T05:30:00Z", ip="10.0.0.1"),  # 00:30 CDT, match
        rec(2, ts="2026-06-14T05:40:00Z", ip="10.0.0.1"),  # 00:40 CDT, match, inside the 10-min window
        rec(3, ts="2026-06-14T12:00:00Z", ip="10.0.0.2"),  # 07:00 CDT, no
        rec(4, ts="2026-06-14T05:30:00Z", ip="10.0.0.3", status="SUCCESS"),  # wrong status
    ]
    alerts = rule.analyze(records)
    assert len(alerts) == 1
    assert alerts[0].source_ip == "10.0.0.1"
    assert alerts[0].count == 2
    assert alerts[0].matched_line_numbers == [1, 2]


def test_unknown_field_never_matches():
    condition = {"field": "bytes_out", "operator": "equals", "value": "500"}
    assert evaluate_condition(rec(1), condition) is False


# ── Rule-level analyze(): grouping and window bucketing ─────────────────────

def test_all_conditions_must_match():
    rule = CustomConditionRule(
        rule_id="R-107",
        display_name="Off-hours privilege escalation",
        severity="high",
        conditions=[
            {"field": "event_type", "operator": "equals", "value": "privilege_escalation"},
            {"field": "status", "operator": "equals", "value": "FAILED"},
        ],
    )
    records = [
        rec(1, ts=_ts(0), event="privilege_escalation", status="FAILED"),
        rec(2, ts=_ts(1), event="privilege_escalation", status="SUCCESS"),
        rec(3, ts=_ts(2), event="login_attempt", status="FAILED"),
    ]
    alerts = rule.analyze(records)
    assert len(alerts) == 1
    assert alerts[0].count == 1
    assert alerts[0].matched_line_numbers == [1]


def test_matches_within_window_are_bucketed_into_one_alert():
    rule = CustomConditionRule(
        rule_id="R-108",
        display_name="Repeated port scans",
        severity="medium",
        conditions=[{"field": "event_type", "operator": "equals", "value": "port_scan"}],
        group_by="ip_address",
        window_seconds=60,
    )
    records = [rec(i + 1, ts=_ts(i * 10), ip="203.0.113.4", event="port_scan") for i in range(5)]
    alerts = rule.analyze(records)
    assert len(alerts) == 1
    assert alerts[0].count == 5
    assert alerts[0].source_ip == "203.0.113.4"


def test_gap_larger_than_window_starts_a_new_bucket():
    rule = CustomConditionRule(
        rule_id="R-109",
        display_name="Repeated port scans",
        severity="medium",
        conditions=[{"field": "event_type", "operator": "equals", "value": "port_scan"}],
        group_by="ip_address",
        window_seconds=60,
    )
    records = [
        rec(1, ts=_ts(0), ip="203.0.113.4", event="port_scan"),
        rec(2, ts=_ts(30), ip="203.0.113.4", event="port_scan"),
        rec(3, ts=_ts(200), ip="203.0.113.4", event="port_scan"),
    ]
    alerts = rule.analyze(records)
    assert len(alerts) == 2
    assert [alert.count for alert in alerts] == [2, 1]


def test_distinct_groups_produce_separate_alerts():
    rule = CustomConditionRule(
        rule_id="R-110",
        display_name="Repeated failed logins",
        severity="high",
        conditions=[{"field": "status", "operator": "equals", "value": "FAILED"}],
        group_by="username",
        window_seconds=300,
    )
    records = [
        rec(1, ts=_ts(0), user="alice", status="FAILED"),
        rec(2, ts=_ts(10), user="bob", status="FAILED"),
    ]
    alerts = rule.analyze(records)
    assert len(alerts) == 2
    assert {alert.username for alert in alerts} == {"alice", "bob"}


def test_no_matches_returns_no_alerts():
    rule = CustomConditionRule(
        rule_id="R-111",
        display_name="Nothing",
        severity="low",
        conditions=[{"field": "event_type", "operator": "equals", "value": "dns_query"}],
    )
    records = [rec(1, event="login_attempt")]
    assert rule.analyze(records) == []


# ── Schema validation for the timezone option ───────────────────────────────

def test_schema_accepts_iana_timezone_on_timestamp_between():
    from app.schemas.custom_rule import ConditionPayload

    cond = ConditionPayload(field="timestamp", operator="between", value="00:00 – 06:00", timezone="America/Chicago")
    assert cond.timezone == "America/Chicago"


def test_schema_timezone_defaults_to_none():
    from app.schemas.custom_rule import ConditionPayload

    cond = ConditionPayload(field="timestamp", operator="between", value="00:00 – 06:00")
    assert cond.timezone is None


def test_schema_rejects_unknown_timezone_name():
    from pydantic import ValidationError

    from app.schemas.custom_rule import ConditionPayload

    with pytest.raises(ValidationError, match="Unknown timezone"):
        ConditionPayload(field="timestamp", operator="between", value="00:00 – 06:00", timezone="Mars/Olympus")


def test_schema_rejects_timezone_on_non_hour_range_conditions():
    from pydantic import ValidationError

    from app.schemas.custom_rule import ConditionPayload

    with pytest.raises(ValidationError, match="timezone can only be set"):
        ConditionPayload(field="timestamp", operator="before", value="2026-06-14T02:00:00Z", timezone="America/Chicago")
    with pytest.raises(ValidationError, match="timezone can only be set"):
        ConditionPayload(field="status", operator="equals", value="FAILED", timezone="America/Chicago")
