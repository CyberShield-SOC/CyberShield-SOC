"""KK-05: deterministic per-source-IP, five-minute feature vectors."""

import math
import random
from datetime import datetime, timedelta, timezone

import pytest

from app.detection.models import LogRecord
from app.ml.features_source_ip_window import (
    ENTITY_TYPE,
    FEATURE_NAMES,
    FEATURE_SET,
    WINDOW_SECONDS,
    extract_window_features,
)

pytestmark = pytest.mark.no_db


def rec(line, ts, ip="192.0.2.10", user="alice", host="host-a", etype="login_attempt",
        status="FAILED", upload="u1", log_id=None):
    return LogRecord(line_number=line, log_id=log_id, upload_id=upload, timestamp=ts, ip_address=ip,
                     username=user, hostname=host, event_type=etype, status=status)


def one(records, **kwargs):
    rows, report = extract_window_features(records, **kwargs)
    assert len(rows) == 1, rows
    return rows[0], report


def test_feature_names_have_no_duplicates_and_match_every_row():
    assert len(set(FEATURE_NAMES)) == len(FEATURE_NAMES)
    row, _ = one([rec(1, "2026-10-02T10:00:00Z")])
    assert tuple(row.features) == FEATURE_NAMES
    assert len(row.vector()) == len(FEATURE_NAMES)


def test_behavioral_counts_for_a_brute_force_window():
    records = [rec(i, f"2026-10-02T10:00:{i * 5:02d}Z", user=f"u{i % 3}") for i in range(1, 7)]
    records += [
        rec(7, "2026-10-02T10:01:00Z", status="SUCCESS", user="u1"),
        rec(8, "2026-10-02T10:02:00Z", etype="privilege_escalation", status="FAILED", user="u1"),
    ]
    row, report = one(records)
    f = row.features
    assert (f["event_count"], f["failed_login_count"], f["success_login_count"]) == (8, 6, 1)
    assert f["failed_to_success_ratio"] == 3.0          # 6 / (1 + 1)
    assert f["unique_users"] == 3 and f["unique_hosts"] == 1
    assert f["sudo_failure_count"] == 1
    assert f["min_gap_seconds"] == 5.0
    assert report.used_records == 8 and report.windows == 1


def test_windows_are_fixed_tumbling_and_half_open():
    rows, _ = extract_window_features([
        rec(1, "2026-10-02T10:04:59Z"), rec(2, "2026-10-02T10:05:00Z"), rec(3, "2026-10-02T10:09:59Z"),
    ])
    assert [(r.window_start.minute, r.record_count) for r in rows] == [(0, 1), (5, 2)]
    assert rows[0].window_end == rows[1].window_start
    assert rows[0].window_end - rows[0].window_start == timedelta(seconds=WINDOW_SECONDS)


def test_window_assignment_does_not_depend_on_other_events():
    alone, _ = extract_window_features([rec(1, "2026-10-02T10:07:30Z")])
    crowded, _ = extract_window_features([rec(1, "2026-10-02T10:07:30Z"), rec(2, "2026-10-02T09:00:00Z", ip="192.0.2.99")])
    assert alone[0].window_start == next(r for r in crowded if r.entity_id == "192.0.2.10").window_start


def test_repeated_runs_and_input_order_give_identical_vectors():
    records = [rec(i, f"2026-10-02T10:{(i * 7) % 20:02d}:{(i * 13) % 60:02d}Z", ip=f"192.0.2.{i % 4 + 1}", user=f"u{i % 5}")
               for i in range(1, 60)]
    first, _ = extract_window_features(records)
    shuffled = records[:]
    random.Random(7).shuffle(shuffled)
    second, _ = extract_window_features(shuffled)
    again, _ = extract_window_features(records)
    assert first == second == again
    assert [r.vector() for r in first] == [r.vector() for r in again]


def test_missing_values_use_the_documented_defaults():
    row, _ = one([rec(1, "2026-10-02T10:00:00Z", user=None, host=None, etype=None, status=None)])
    f = row.features
    assert f["unique_users"] == 0 and f["unique_hosts"] == 0
    assert f["failed_login_count"] == f["success_login_count"] == f["sudo_failure_count"] == 0
    assert f["failed_to_success_ratio"] == 0.0
    assert f["mean_gap_seconds"] == f["min_gap_seconds"] == float(WINDOW_SECONDS)
    assert f["known_status_ratio"] == 0.0 and f["known_event_type_ratio"] == 0.0
    assert all(math.isfinite(v) for v in row.vector())


def test_unusable_records_are_dropped_and_counted_never_guessed():
    rows, report = extract_window_features([
        rec(1, "2026-10-02T10:00:00Z"),
        rec(2, "garbage"), rec(3, None),
        rec(4, "2026-10-02T10:00:10Z", ip="unknown"), rec(5, "2026-10-02T10:00:10Z", ip=None),
        rec(6, "2026-10-02T10:00:10Z", ip="999.9.9.9"),
    ])
    assert len(rows) == 1 and rows[0].record_count == 1
    assert (report.total_records, report.used_records) == (6, 1)
    assert report.dropped_missing_timestamp == 2 and report.dropped_invalid_ip == 3


def test_duplicates_are_counted_once_by_log_id_or_upload_line():
    rows, report = extract_window_features([
        rec(1, "2026-10-02T10:00:00Z", log_id=5), rec(2, "2026-10-02T10:00:30Z", log_id=5),   # same log id
        rec(3, "2026-10-02T10:01:00Z"), rec(3, "2026-10-02T10:01:00Z"),                       # same upload+line
        rec(3, "2026-10-02T10:01:00Z", upload="u2"),                                          # different upload: kept
    ])
    assert rows[0].record_count == 3 and report.duplicate_records == 2


def test_ip_spellings_and_timezones_normalize():
    rows, _ = extract_window_features([
        rec(1, "2026-10-02T11:00:00+01:00", ip="2001:0db8::1"),
        rec(2, "2026-10-02T10:01:00Z", ip="2001:db8::1"),
    ])
    assert len(rows) == 1 and rows[0].entity_id == "2001:db8::1" and rows[0].record_count == 2
    assert rows[0].window_start == datetime(2026, 10, 2, 10, 0, tzinfo=timezone.utc)


def test_hour_encoding_is_cyclic_and_uses_window_start():
    late, _ = one([rec(1, "2026-10-02T23:59:00Z")])
    early, _ = extract_window_features([rec(1, "2026-10-03T00:01:00Z")])
    assert abs(late.features["hour_sin"] - early[0].features["hour_sin"]) < 0.1
    assert abs(late.features["hour_cos"] - early[0].features["hour_cos"]) < 0.1


def test_snapshot_kwargs_match_the_existing_snapshot_contract():
    row, _ = one([rec(1, "2026-10-02T10:00:00Z")])
    kwargs = row.snapshot_kwargs()
    assert kwargs["feature_set"] == FEATURE_SET and kwargs["entity_type"] == ENTITY_TYPE
    assert kwargs["entity_type"] in {"source_ip", "account", "host"}   # ck_ml_feature_snapshots_entity_type
    assert kwargs["captured_at"] == row.window_start and kwargs["entity_id"] == "192.0.2.10"


def test_custom_window_and_invalid_window():
    rows, _ = extract_window_features([rec(1, "2026-10-02T10:00:00Z"), rec(2, "2026-10-02T10:00:45Z")], window_seconds=30)
    assert len(rows) == 2
    with pytest.raises(ValueError):
        extract_window_features([], window_seconds=0)
    assert extract_window_features([])[0] == []
