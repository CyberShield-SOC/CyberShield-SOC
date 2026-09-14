"""Rules backed by cross-upload state (entity_baselines) and the cooldown
suppression step. These use a real, rollback-only Postgres session."""

from __future__ import annotations

import sys
from pathlib import Path
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy.orm import Session

from app.detection.models import Alert as DetectionAlert
from app.detection.models import LogRecord
from app.detection.rules.dormant_account_activity import DormantAccountActivityRule
from app.detection.rules.lateral_movement_chain import LateralMovementChainRule
from app.repositories.alert_repository import (
    create_alerts_from_detection,
    suppress_alerts_in_cooldown,
)
from app.repositories.baseline_repository import get_baseline, set_baseline
from app.detection.alert_store import serialize_alert


def unique_user() -> str:
    return f"acct-{uuid4().hex[:8]}"


def login(n, user, ts, host=None, ip="10.0.0.9"):
    return LogRecord(
        line_number=n, timestamp=ts, ip_address=ip, username=user, hostname=host,
        event_type="login_attempt", status="SUCCESS",
    )


# ── dormant_account_activity ─────────────────────────────────────────────────

def test_dormant_account_fires_after_idle_threshold(db_session: Session):
    user = unique_user()
    set_baseline(db_session, entity_type="account", entity_id=user,
                 baseline_key="last_login_at", value={"last_login_at": "2026-04-01T09:00:00Z"})

    alerts = DormantAccountActivityRule(threshold=30).analyze(
        [login(1, user, "2026-06-14T09:00:00Z")], db_session
    )

    assert len(alerts) == 1
    assert alerts[0].entity_id == user
    assert "74 days" in alerts[0].description


def test_dormant_account_near_miss_recently_active(db_session: Session):
    user = unique_user()
    set_baseline(db_session, entity_type="account", entity_id=user,
                 baseline_key="last_login_at", value={"last_login_at": "2026-06-01T09:00:00Z"})

    assert DormantAccountActivityRule(threshold=30).analyze(
        [login(1, user, "2026-06-14T09:00:00Z")], db_session
    ) == []


def test_dormant_account_first_sighting_records_baseline_without_alerting(db_session: Session):
    user = unique_user()
    rule = DormantAccountActivityRule(threshold=30)

    assert rule.analyze([login(1, user, "2026-06-14T09:00:00Z")], db_session) == []
    stored = get_baseline(db_session, entity_type="account", entity_id=user, baseline_key="last_login_at")
    assert stored == {"last_login_at": "2026-06-14T09:00:00Z"}

    # A later upload 60 days on now has history to compare against.
    assert len(rule.analyze([login(2, user, "2026-08-13T09:00:00Z")], db_session)) == 1


def test_dormant_account_without_db_is_a_no_op():
    assert DormantAccountActivityRule().analyze([login(1, "anyone", "2026-06-14T09:00:00Z")]) == []


# ── lateral_movement_chain ───────────────────────────────────────────────────

def test_lateral_movement_fires_within_one_upload(db_session: Session):
    user = unique_user()
    records = [
        login(1, user, "2026-06-14T09:00:00Z", host="web01"),
        login(2, user, "2026-06-14T09:02:00Z", host="db01"),
        login(3, user, "2026-06-14T09:04:00Z", host="backup01"),
    ]

    alerts = LateralMovementChainRule(threshold=3, window_seconds=600).analyze(records, db_session)

    assert len(alerts) == 1
    assert alerts[0].mitre_technique == "T1021.004"
    assert set(alerts[0].matched_line_numbers) == {1, 2, 3}


def test_lateral_movement_chains_across_uploads(db_session: Session):
    user = unique_user()
    rule = LateralMovementChainRule(threshold=3, window_seconds=600)

    first_upload = [
        login(1, user, "2026-06-14T09:00:00Z", host="web01"),
        login(2, user, "2026-06-14T09:02:00Z", host="db01"),
    ]
    assert rule.analyze(first_upload, db_session) == []

    second_upload = [login(1, user, "2026-06-14T09:04:00Z", host="backup01")]
    alerts = rule.analyze(second_upload, db_session)
    assert len(alerts) == 1
    # Only this upload's own line numbers — earlier uploads' lines belong to other files.
    assert alerts[0].matched_line_numbers == [1]


def test_lateral_movement_near_miss_same_host_repeatedly(db_session: Session):
    user = unique_user()
    records = [login(i + 1, user, f"2026-06-14T09:0{i}:00Z", host="web01") for i in range(5)]
    assert LateralMovementChainRule(threshold=3).analyze(records, db_session) == []


def test_lateral_movement_near_miss_hosts_spread_beyond_window(db_session: Session):
    user = unique_user()
    records = [
        login(1, user, "2026-06-14T09:00:00Z", host="web01"),
        login(2, user, "2026-06-14T09:20:00Z", host="db01"),
        login(3, user, "2026-06-14T09:40:00Z", host="backup01"),
    ]
    assert LateralMovementChainRule(threshold=3, window_seconds=600).analyze(records, db_session) == []


def test_lateral_movement_without_db_still_works_within_batch():
    user = "no-db-user"
    records = [
        login(1, user, "2026-06-14T09:00:00Z", host="web01"),
        login(2, user, "2026-06-14T09:01:00Z", host="db01"),
        login(3, user, "2026-06-14T09:02:00Z", host="backup01"),
    ]
    assert len(LateralMovementChainRule(threshold=3).analyze(records)) == 1


# ── cooldown suppression ────────────────────────────────────────────────────

def _alert(entity_id: str, last_seen: str) -> DetectionAlert:
    return DetectionAlert(
        rule="new_account_created", severity="HIGH", count=1, time_window_seconds=0,
        first_seen=last_seen, last_seen=last_seen, description="test",
        matched_line_numbers=[1], entity_type="host", entity_id=entity_id,
    )


def test_cooldown_suppresses_repeat_alert_for_same_entity_in_one_batch(db_session: Session):
    host = f"host-{uuid4().hex[:8]}"
    alerts = [_alert(host, "2026-06-14T09:00:00Z"), _alert(host, "2026-06-14T09:10:00Z")]
    kept = suppress_alerts_in_cooldown(db_session, alerts, {"new_account_created": 1800})
    assert len(kept) == 1


def test_cooldown_keeps_alerts_for_different_entities(db_session: Session):
    alerts = [_alert(f"a-{uuid4().hex[:6]}", "2026-06-14T09:00:00Z"),
              _alert(f"b-{uuid4().hex[:6]}", "2026-06-14T09:01:00Z")]
    assert len(suppress_alerts_in_cooldown(db_session, alerts, {"new_account_created": 1800})) == 2


def test_cooldown_suppresses_against_previously_stored_alert(db_session: Session):
    host = f"host-{uuid4().hex[:8]}"
    create_alerts_from_detection(
        db_session, upload_id=uuid4(),
        serialized_alerts=[serialize_alert(_alert(host, "2026-06-14T09:00:00Z"))],
    )

    within = suppress_alerts_in_cooldown(db_session, [_alert(host, "2026-06-14T09:20:00Z")], {"new_account_created": 1800})
    after = suppress_alerts_in_cooldown(db_session, [_alert(host, "2026-06-14T10:00:00Z")], {"new_account_created": 1800})

    assert within == []
    assert len(after) == 1


def test_no_cooldown_configured_changes_nothing(db_session: Session):
    host = f"host-{uuid4().hex[:8]}"
    alerts = [_alert(host, "2026-06-14T09:00:00Z"), _alert(host, "2026-06-14T09:00:01Z")]
    assert len(suppress_alerts_in_cooldown(db_session, alerts, {"new_account_created": None})) == 2
