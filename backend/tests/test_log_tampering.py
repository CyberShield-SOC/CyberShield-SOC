import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

pytestmark = pytest.mark.no_db

from app.detection.models import LogRecord
from app.detection.rules.log_tampering import LogTamperingRule
from app.parsers.syslog_parser import parse_syslog


def rec(n, process=None, message=None, hostname="web01", ts="2026-06-14T02:11:00Z"):
    return LogRecord(
        line_number=n, timestamp=ts, hostname=hostname, process=process, message=message,
    )


class TestLogTamperingRule:
    def test_fires_when_auditd_stopped(self):
        rule = LogTamperingRule()
        alerts = rule.analyze([rec(1, process="systemd", message="Stopped Security Auditing Service (auditd).")])
        assert len(alerts) == 1
        assert alerts[0].severity == "CRITICAL"
        assert alerts[0].mitre_technique == "T1070"

    def test_fires_on_journal_vacuum(self):
        rule = LogTamperingRule()
        alerts = rule.analyze([rec(1, process="systemd-journald", message="Vacuuming done, freed 1.2G of archived journals from /var/log/journal.")])
        assert len(alerts) == 1
        assert "vacuumed" in alerts[0].description

    def test_near_miss_journald_routine_rotation_does_not_fire(self):
        rule = LogTamperingRule()
        assert rule.analyze([rec(1, process="systemd-journald", message="Journal started")]) == []

    def test_near_miss_unrelated_service_stopped_does_not_fire(self):
        rule = LogTamperingRule()
        assert rule.analyze([rec(1, process="systemd", message="Stopped nginx.")]) == []

    def test_near_miss_security_agent_stop_is_not_log_tampering(self):
        # fail2ban is a security control, not a logging service — that
        # belongs to security_control_disabled, not this rule.
        rule = LogTamperingRule()
        assert rule.analyze([rec(1, process="systemd", message="Stopped fail2ban.")]) == []

    def test_end_to_end_through_syslog_parser(self):
        line = "Jun 14 02:11:00 web01 systemd[1]: Stopped System Logging Service (rsyslog)."
        entry = parse_syslog("", [line])["entries"][0]["parsed"]
        record = LogRecord(
            line_number=1, timestamp=entry["timestamp"], hostname=entry["hostname"],
            process=entry["process"], message=entry["message"],
        )
        assert len(LogTamperingRule().analyze([record])) == 1
