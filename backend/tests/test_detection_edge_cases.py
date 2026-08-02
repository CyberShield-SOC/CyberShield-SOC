"""TEST-2 supplement: boundary, missing-field, unexpected-value, and
duplicate-finding coverage for the detection engine, on top of the existing
extensive rule coverage in test_detection.py.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.detection.models import LogRecord
from app.detection.rules.brute_force import BruteForceLoginRule
from app.detection.rules.credential_stuffing import CredentialStuffingRule
from app.detection.rules.invalid_user import InvalidUserRule
from app.detection.rules.port_scan import PortScanRule
from app.detection.rules.sudo_failure import SudoFailureRule

_BASE = datetime(2026, 6, 14, 2, 11, 0, tzinfo=timezone.utc)


def _ts(delta_s: int) -> str:
    return (_BASE + timedelta(seconds=delta_s)).strftime("%Y-%m-%dT%H:%M:%SZ")


def rec(n, ts=None, ip=None, user=None, event="login_attempt", status="FAILED") -> LogRecord:
    return LogRecord(
        line_number=n,
        timestamp=ts,
        ip_address=ip,
        username=user,
        event_type=event,
        status=status,
    )


# ── Duplicate findings: sliding windows must not double-fire on overlap ─────

def test_brute_force_does_not_duplicate_alerts_across_an_extended_burst():
    """10 failed logins in one tight window is two independent bursts of 5,
    not five overlapping/duplicate alerts for the same underlying activity."""

    rule = BruteForceLoginRule(threshold=5, window_seconds=60)
    records = [rec(i + 1, _ts(i * 2), "203.0.113.4", "root") for i in range(10)]
    alerts = rule.analyze(records)

    assert len(alerts) == 2
    assert alerts[0].matched_line_numbers == [1, 2, 3, 4, 5]
    assert alerts[1].matched_line_numbers == [6, 7, 8, 9, 10]


def test_invalid_user_does_not_duplicate_alerts_across_repeated_enumeration():
    rule = InvalidUserRule(threshold=3, window_seconds=600)
    records = [
        rec(i + 1, _ts(i * 10), "5.5.5.5", name)
        for i, name in enumerate(["alice", "bob", "charlie", "dave", "erin", "frank"])
    ]
    alerts = rule.analyze(records)

    assert len(alerts) == 2


# ── Missing fields do not crash and do not fire ─────────────────────────────

def test_brute_force_skips_records_missing_ip_address():
    rule = BruteForceLoginRule(threshold=3, window_seconds=60)
    records = [rec(i + 1, _ts(i), None, "root") for i in range(5)]
    assert rule.analyze(records) == []


def test_port_scan_skips_records_missing_ip_address():
    rule = PortScanRule(threshold=3, window_seconds=60)
    records = [rec(i + 1, _ts(i), None, None, event="port_scan", status="UNKNOWN") for i in range(5)]
    assert rule.analyze(records) == []


def test_sudo_failure_falls_back_to_ip_when_username_is_missing():
    """Documented behavior: anonymous sudo attempts (no username) are still
    grouped and detected by source IP rather than being silently dropped."""

    rule = SudoFailureRule(threshold=3, window_seconds=300)
    records = [
        rec(i + 1, _ts(i * 10), "10.0.0.5", None, event="privilege_escalation", status="FAILED")
        for i in range(3)
    ]
    alerts = rule.analyze(records)
    assert len(alerts) == 1
    assert alerts[0].source_ip == "10.0.0.5"
    assert alerts[0].username is None


def test_sudo_failure_skips_records_missing_both_username_and_ip():
    rule = SudoFailureRule(threshold=3, window_seconds=300)
    records = [
        rec(i + 1, _ts(i * 10), None, None, event="privilege_escalation", status="FAILED")
        for i in range(5)
    ]
    assert rule.analyze(records) == []


def test_credential_stuffing_skips_records_missing_ip_address():
    rule = CredentialStuffingRule(fail_threshold=3, window_seconds=60)
    records = [rec(i + 1, _ts(i), None, "root") for i in range(3)] + [
        rec(4, _ts(10), None, "root", status="SUCCESS")
    ]
    assert rule.analyze(records) == []


# ── Unexpected / malformed values do not crash the engine ───────────────────

def test_brute_force_ignores_records_with_unparseable_timestamps():
    rule = BruteForceLoginRule(threshold=3, window_seconds=60)
    records = [rec(i + 1, "definitely-not-a-timestamp", "10.0.0.9", "root") for i in range(5)]
    assert rule.analyze(records) == []


def test_brute_force_handles_mixed_valid_and_malformed_timestamps_without_crashing():
    rule = BruteForceLoginRule(threshold=3, window_seconds=60)
    records = [
        rec(1, "garbage", "10.0.0.9", "root"),
        rec(2, _ts(0), "10.0.0.9", "root"),
        rec(3, _ts(2), "10.0.0.9", "root"),
        rec(4, "", "10.0.0.9", "root"),
        rec(5, _ts(4), "10.0.0.9", "root"),
    ]
    # Only the three valid timestamps (records 2, 3, 5) count toward the
    # threshold; the malformed/blank ones are dropped, not crashed on.
    alerts = rule.analyze(records)
    assert len(alerts) == 1
    assert alerts[0].count == 3
    assert alerts[0].matched_line_numbers == [2, 3, 5]


def test_invalid_user_ignores_empty_string_username_as_missing():
    rule = InvalidUserRule(threshold=3, window_seconds=600)
    records = [rec(i + 1, _ts(i * 10), "5.5.5.5", "") for i in range(5)]
    assert rule.analyze(records) == []


# ── Boundary values ──────────────────────────────────────────────────────────

def test_port_scan_fires_exactly_at_threshold_boundary_not_one_below():
    rule = PortScanRule(threshold=10, window_seconds=60)
    below = [rec(i + 1, _ts(i), "198.51.100.9", None, event="port_scan", status="UNKNOWN") for i in range(9)]
    at_threshold = below + [rec(10, _ts(9), "198.51.100.9", None, event="port_scan", status="UNKNOWN")]

    assert PortScanRule(threshold=10, window_seconds=60).analyze(below) == []
    assert len(PortScanRule(threshold=10, window_seconds=60).analyze(at_threshold)) == 1


def test_credential_stuffing_boundary_success_exactly_at_window_edge():
    """A success landing exactly on the success-window boundary is inclusive
    (>=), matching the documented ">= threshold" semantics used everywhere
    else in the engine."""

    rule = CredentialStuffingRule(fail_threshold=3, window_seconds=60, success_window_seconds=30)
    records = [rec(i + 1, _ts(i * 2), "203.0.113.4", "root") for i in range(3)]
    records.append(rec(4, _ts(30), "203.0.113.4", "root", status="SUCCESS"))
    alerts = rule.analyze(records)
    assert len(alerts) == 1


# ── Engine-level robustness ──────────────────────────────────────────────────

def test_engine_handles_empty_record_list():
    from app.detection.engine import DetectionEngine

    assert DetectionEngine().run([]) == []


def test_engine_handles_duplicate_identical_records_without_crashing():
    """Upstream duplicate ingestion (e.g. the same line uploaded twice across
    two files) must not crash the engine; each occurrence legitimately
    counts toward its own rule's threshold."""

    from app.detection.engine import DetectionEngine

    record = rec(1, _ts(0), "203.0.113.4", "root")
    duplicated = [record for _ in range(5)]
    alerts = DetectionEngine(rules=[BruteForceLoginRule(threshold=5, window_seconds=60)]).run(duplicated)
    assert len(alerts) == 1
    assert alerts[0].count == 5
