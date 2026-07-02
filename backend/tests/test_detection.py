import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.detection.engine import DetectionEngine
from app.detection.models import Alert, LogRecord
from app.detection.rules.brute_force import BruteForceLoginRule
from app.detection.rules.invalid_user import InvalidUserRule
from app.detection.rules.sudo_failure import SudoFailureRule

# ── helpers ───────────────────────────────────────────────────────────────────

_BASE = datetime(2026, 6, 14, 2, 11, 0, tzinfo=timezone.utc)


def _ts(delta_s: int) -> str:
    return (_BASE + timedelta(seconds=delta_s)).strftime("%Y-%m-%dT%H:%M:%SZ")


def rec(
    n: int,
    ts: str | None = None,
    ip: str | None = None,
    user: str | None = None,
    event: str = "login_attempt",
    status: str = "FAILED",
) -> LogRecord:
    return LogRecord(
        line_number=n,
        timestamp=ts,
        ip_address=ip,
        username=user,
        event_type=event,
        status=status,
    )


# ── PBI-13.2: BruteForceLoginRule ────────────────────────────────────────────

class TestBruteForceLoginRule:

    def test_fires_at_threshold(self):
        rule = BruteForceLoginRule(threshold=5, window_seconds=60)
        records = [rec(i + 1, _ts(i * 2), "203.0.113.4", "root") for i in range(5)]
        alerts = rule.analyze(records)
        assert len(alerts) == 1
        assert alerts[0].rule == "brute_force_login"
        assert alerts[0].severity == "HIGH"
        assert alerts[0].count == 5
        assert alerts[0].source_ip == "203.0.113.4"

    def test_no_fire_below_threshold(self):
        rule = BruteForceLoginRule(threshold=5, window_seconds=60)
        records = [rec(i + 1, _ts(i * 2), "203.0.113.4", "root") for i in range(4)]
        assert rule.analyze(records) == []

    def test_no_fire_outside_window(self):
        # 5 events 30 s apart → max 3 in any 60-second window
        rule = BruteForceLoginRule(threshold=5, window_seconds=60)
        records = [rec(i + 1, _ts(i * 30), "10.0.0.1", "admin") for i in range(5)]
        assert rule.analyze(records) == []

    def test_sample_fixture(self):
        """Brute-force scenario matching the 10-entry frontend sample data."""
        records = [
            rec(1, "2026-06-14T02:11:43Z", "203.0.113.4", "root"),
            rec(2, "2026-06-14T02:11:45Z", "203.0.113.4", "root"),
            rec(3, "2026-06-14T02:11:47Z", "203.0.113.4", "root"),
            rec(4, "2026-06-14T02:11:49Z", "203.0.113.4", "root"),
            rec(5, "2026-06-14T02:11:51Z", "203.0.113.4", "root"),
            rec(6, "2026-06-14T02:12:01Z", "203.0.113.4", "admin"),
            rec(7, "2026-06-14T02:15:11Z", None,          "jdoe", event="privilege_escalation"),
            rec(8, "2026-06-14T02:15:14Z", None,          "jdoe", event="privilege_escalation"),
            rec(9, "2026-06-14T02:18:25Z", "10.0.0.5",   "jdoe", status="SUCCESS"),
            rec(10, "2026-06-14T02:19:01Z", "10.0.0.5",  None,   event="connection_closed", status="INFO"),
        ]
        rule = BruteForceLoginRule(threshold=5, window_seconds=60)
        alerts = rule.analyze(records)
        assert len(alerts) == 1
        assert alerts[0].source_ip == "203.0.113.4"
        assert alerts[0].count == 5
        assert set(alerts[0].matched_line_numbers) == {1, 2, 3, 4, 5}

    def test_ignores_successful_logins(self):
        rule = BruteForceLoginRule(threshold=5, window_seconds=60)
        records = [rec(i + 1, _ts(i), "10.0.0.1", "admin", status="SUCCESS") for i in range(10)]
        assert rule.analyze(records) == []

    def test_isolates_by_ip(self):
        # 3 failures each from two different IPs — neither reaches threshold of 5
        rule = BruteForceLoginRule(threshold=5, window_seconds=60)
        records = (
            [rec(i + 1, _ts(i), "1.1.1.1", "root") for i in range(3)]
            + [rec(i + 4, _ts(i), "2.2.2.2", "root") for i in range(3)]
        )
        assert rule.analyze(records) == []

    def test_skips_records_without_timestamp(self):
        rule = BruteForceLoginRule(threshold=3, window_seconds=60)
        records = [rec(i + 1, None, "5.5.5.5", "root") for i in range(5)]
        assert rule.analyze(records) == []


# ── PBI-13.3: InvalidUserRule ─────────────────────────────────────────────────

class TestInvalidUserRule:

    def test_fires_on_distinct_usernames(self):
        rule = InvalidUserRule(threshold=3, window_seconds=600)
        records = [
            rec(1, _ts(0),   "5.5.5.5", "alice"),
            rec(2, _ts(60),  "5.5.5.5", "bob"),
            rec(3, _ts(120), "5.5.5.5", "charlie"),
        ]
        alerts = rule.analyze(records)
        assert len(alerts) == 1
        assert alerts[0].rule == "invalid_user_enumeration"
        assert alerts[0].severity == "MEDIUM"
        assert alerts[0].count == 3

    def test_no_fire_same_username_repeated(self):
        rule = InvalidUserRule(threshold=3, window_seconds=600)
        records = [rec(i + 1, _ts(i * 10), "5.5.5.5", "root") for i in range(10)]
        assert rule.analyze(records) == []

    def test_no_fire_below_threshold(self):
        rule = InvalidUserRule(threshold=3, window_seconds=600)
        records = [
            rec(1, _ts(0),  "5.5.5.5", "alice"),
            rec(2, _ts(60), "5.5.5.5", "bob"),
        ]
        assert rule.analyze(records) == []

    def test_no_fire_outside_window(self):
        # 3 distinct users, each 2 minutes apart — outside a 60-second window
        rule = InvalidUserRule(threshold=3, window_seconds=60)
        records = [
            rec(1, _ts(0),   "5.5.5.5", "alice"),
            rec(2, _ts(120), "5.5.5.5", "bob"),
            rec(3, _ts(240), "5.5.5.5", "charlie"),
        ]
        assert rule.analyze(records) == []

    def test_no_fire_on_successful_logins(self):
        rule = InvalidUserRule(threshold=3, window_seconds=600)
        records = [
            rec(i + 1, _ts(i * 10), "5.5.5.5", f"user{i}", status="SUCCESS")
            for i in range(5)
        ]
        assert rule.analyze(records) == []

    def test_no_fire_without_username(self):
        rule = InvalidUserRule(threshold=3, window_seconds=600)
        records = [rec(i + 1, _ts(i * 10), "5.5.5.5", None) for i in range(5)]
        assert rule.analyze(records) == []


# ── PBI-13.4: SudoFailureRule ─────────────────────────────────────────────────

class TestSudoFailureRule:

    def test_fires_on_sudo_failures(self):
        rule = SudoFailureRule(threshold=3, window_seconds=300)
        records = [
            rec(i + 1, _ts(i * 30), "10.0.0.5", "jdoe",
                event="privilege_escalation", status="FAILED")
            for i in range(3)
        ]
        alerts = rule.analyze(records)
        assert len(alerts) == 1
        assert alerts[0].rule == "sudo_failure"
        assert alerts[0].severity == "MEDIUM"
        assert alerts[0].username == "jdoe"

    def test_no_fire_below_threshold(self):
        rule = SudoFailureRule(threshold=3, window_seconds=300)
        records = [
            rec(i + 1, _ts(i * 30), "10.0.0.5", "jdoe",
                event="privilege_escalation", status="FAILED")
            for i in range(2)
        ]
        assert rule.analyze(records) == []

    def test_no_fire_outside_window(self):
        # 3 failures, 3 minutes apart = 6 minutes total — outside 60s window
        rule = SudoFailureRule(threshold=3, window_seconds=60)
        records = [
            rec(i + 1, _ts(i * 180), "10.0.0.5", "jdoe",
                event="privilege_escalation", status="FAILED")
            for i in range(3)
        ]
        assert rule.analyze(records) == []

    def test_no_fire_on_sudo_success(self):
        rule = SudoFailureRule(threshold=3, window_seconds=300)
        records = [
            rec(i + 1, _ts(i * 10), "10.0.0.5", "jdoe",
                event="privilege_escalation", status="SUCCESS")
            for i in range(5)
        ]
        assert rule.analyze(records) == []

    def test_groups_by_username_not_ip(self):
        # 2 failures each for two users sharing the same IP — neither hits threshold of 3
        rule = SudoFailureRule(threshold=3, window_seconds=300)
        records = [
            rec(1, _ts(0),  "10.0.0.5", "alice", event="privilege_escalation", status="FAILED"),
            rec(2, _ts(10), "10.0.0.5", "alice", event="privilege_escalation", status="FAILED"),
            rec(3, _ts(20), "10.0.0.5", "bob",   event="privilege_escalation", status="FAILED"),
            rec(4, _ts(30), "10.0.0.5", "bob",   event="privilege_escalation", status="FAILED"),
        ]
        assert rule.analyze(records) == []


# ── Full engine integration ───────────────────────────────────────────────────

class TestDetectionEngine:

    def test_engine_runs_all_rules(self):
        engine = DetectionEngine()
        records = [
            # Brute-force: 5 failed logins from one IP
            *[rec(i + 1, _ts(i * 2), "203.0.113.4", "root") for i in range(5)],
            # Sudo failure: 3 failures for jdoe
            *[
                rec(i + 6, _ts(i * 30), "10.0.0.5", "jdoe",
                    event="privilege_escalation", status="FAILED")
                for i in range(3)
            ],
        ]
        alerts = engine.run(records)
        rules_fired = {a.rule for a in alerts}
        assert "brute_force_login" in rules_fired
        assert "sudo_failure" in rules_fired

    def test_engine_returns_empty_for_clean_logs(self):
        engine = DetectionEngine()
        records = [
            rec(1, _ts(0), "10.0.0.1", "admin", status="SUCCESS"),
        ]
        assert engine.run(records) == []

    def test_engine_alert_fields_complete(self):
        engine = DetectionEngine()
        records = [rec(i + 1, _ts(i * 2), "1.2.3.4", "root") for i in range(5)]
        alerts = engine.run(records)
        assert alerts
        a = alerts[0]
        assert a.rule
        assert a.severity in {"HIGH", "MEDIUM", "LOW"}
        assert a.count >= 1
        assert a.time_window_seconds > 0
        assert a.first_seen
        assert a.last_seen
        assert a.description
        assert a.matched_line_numbers


# ── /upload endpoint includes alerts ─────────────────────────────────────────

class TestUploadEndpointAlerts:

    def test_upload_returns_alerts_key(self):
        from io import BytesIO
        from fastapi.testclient import TestClient
        from app.main import app

        client = TestClient(app)
        log = (
            b"Jun 14 02:11:43 server01 sshd[1]: Failed password for root from 203.0.113.4 port 22 ssh2\n"
            b"Jun 14 02:11:45 server01 sshd[1]: Failed password for root from 203.0.113.4 port 22 ssh2\n"
            b"Jun 14 02:11:47 server01 sshd[1]: Failed password for root from 203.0.113.4 port 22 ssh2\n"
            b"Jun 14 02:11:49 server01 sshd[1]: Failed password for root from 203.0.113.4 port 22 ssh2\n"
            b"Jun 14 02:11:51 server01 sshd[1]: Failed password for root from 203.0.113.4 port 22 ssh2\n"
        )
        resp = client.post("/upload", files={"logfile": ("auth.log", BytesIO(log), "text/plain")})
        assert resp.status_code == 200
        data = resp.json()
        assert "alerts" in data
        assert isinstance(data["alerts"], list)
        assert any(a["rule"] == "brute_force_login" for a in data["alerts"])
