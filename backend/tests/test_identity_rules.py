"""Group B identity-context rules that need no cross-upload state:
direct_root_login, service_account_interactive,
login_to_nonexistent_account, off_hours_login."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

pytestmark = pytest.mark.no_db

from app.detection.engine import DetectionEngine
from app.detection.models import LogRecord
from app.detection.rules.direct_root_login import DirectRootLoginRule
from app.detection.rules.login_to_nonexistent_account import LoginToNonexistentAccountRule
from app.detection.rules.off_hours_login import OffHoursLoginRule
from app.detection.rules.service_account_interactive import ServiceAccountInteractiveRule

BUSINESS_HOURS = "2026-06-14T14:00:00Z"


def login(n, user, status="SUCCESS", ip="203.0.113.7", ts=BUSINESS_HOURS):
    return LogRecord(
        line_number=n, timestamp=ts, ip_address=ip, username=user,
        event_type="login_attempt", status=status,
    )


class TestDirectRootLoginRule:
    def test_fires_on_successful_root_login(self):
        alerts = DirectRootLoginRule().analyze([login(1, "root")])
        assert len(alerts) == 1
        assert alerts[0].entity_type == "account"
        assert alerts[0].entity_id == "root"
        assert alerts[0].mitre_technique == "T1078.003"

    def test_near_miss_failed_root_login_does_not_fire(self):
        # Failed root attempts are brute_force/enumeration territory, not this rule.
        assert DirectRootLoginRule().analyze([login(1, "root", status="FAILED")]) == []

    def test_near_miss_rootkit_named_user_does_not_fire(self):
        # Exact account match only — no substring matching on "root".
        assert DirectRootLoginRule().analyze([login(1, "rootadmin")]) == []

    def test_allowlist_overrides_superuser_names(self):
        rule = DirectRootLoginRule(allowlist=["Administrator"])
        assert len(rule.analyze([login(1, "administrator")])) == 1
        assert rule.analyze([login(2, "root")]) == []


class TestServiceAccountInteractiveRule:
    def test_fires_for_configured_service_account(self):
        rule = ServiceAccountInteractiveRule(allowlist=["www-data", "postgres"])
        alerts = rule.analyze([login(1, "postgres")])
        assert len(alerts) == 1
        assert alerts[0].username == "postgres"

    def test_near_miss_human_account_does_not_fire(self):
        rule = ServiceAccountInteractiveRule(allowlist=["www-data", "postgres"])
        assert rule.analyze([login(1, "alice")]) == []

    def test_unconfigured_rule_matches_nothing(self):
        # No roster => fail safe, never guess which accounts are services.
        assert ServiceAccountInteractiveRule().analyze([login(1, "postgres")]) == []


class TestLoginToNonexistentAccountRule:
    def test_fires_on_attempt_against_decommissioned_account(self):
        rule = LoginToNonexistentAccountRule(allowlist=["former-contractor"])
        alerts = rule.analyze([login(1, "former-contractor", status="FAILED")])
        assert len(alerts) == 1
        assert alerts[0].severity == "MEDIUM"

    def test_near_miss_failed_login_for_active_account_does_not_fire(self):
        rule = LoginToNonexistentAccountRule(allowlist=["former-contractor"])
        assert rule.analyze([login(1, "alice", status="FAILED")]) == []

    def test_unconfigured_rule_matches_nothing(self):
        assert LoginToNonexistentAccountRule().analyze([login(1, "anyone", status="FAILED")]) == []


class TestOffHoursLoginRule:
    def test_fires_outside_default_window(self):
        alerts = OffHoursLoginRule().analyze([login(1, "alice", ts="2026-06-14T02:30:00Z")])
        assert len(alerts) == 1
        assert alerts[0].severity == "LOW"

    def test_near_miss_inside_default_window_does_not_fire(self):
        assert OffHoursLoginRule().analyze([login(1, "alice", ts="2026-06-14T19:59:00Z")]) == []

    def test_end_hour_is_exclusive(self):
        assert len(OffHoursLoginRule().analyze([login(1, "alice", ts="2026-06-14T20:00:00Z")])) == 1

    def test_failed_off_hours_login_does_not_fire(self):
        assert OffHoursLoginRule().analyze([login(1, "alice", status="FAILED", ts="2026-06-14T02:30:00Z")]) == []

    def test_window_wrapping_midnight(self):
        night_shift = OffHoursLoginRule(start_hour=22, end_hour=6)
        assert night_shift.analyze([login(1, "alice", ts="2026-06-14T23:00:00Z")]) == []
        assert night_shift.analyze([login(2, "alice", ts="2026-06-14T03:00:00Z")]) == []
        assert len(night_shift.analyze([login(3, "alice", ts="2026-06-14T12:00:00Z")])) == 1

    def test_config_threads_start_and_end_hour_through_engine(self):
        engine = DetectionEngine.from_config({"off_hours_login": {"start_hour": 0, "end_hour": 23}})
        rule = next(r for r in engine.rules if r.name == "off_hours_login")
        assert (rule.start_hour, rule.end_hour) == (0, 23)
