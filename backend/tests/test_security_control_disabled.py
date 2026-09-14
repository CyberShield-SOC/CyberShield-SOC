import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

pytestmark = pytest.mark.no_db

from app.detection.models import LogRecord
from app.detection.rules.security_control_disabled import SecurityControlDisabledRule
from app.parsers.syslog_parser import parse_syslog


def rec(n, process=None, message=None, hostname="web01", ts="2026-06-14T02:11:00Z"):
    return LogRecord(
        line_number=n, timestamp=ts, hostname=hostname, process=process, message=message,
    )


class TestSecurityControlDisabledRule:
    def test_fires_when_firewall_manager_stopped(self):
        rule = SecurityControlDisabledRule()
        alerts = rule.analyze([rec(1, process="systemd", message="Stopped Uncomplicated firewall (ufw).")])
        assert len(alerts) == 1
        assert alerts[0].mitre_technique == "T1562"
        assert alerts[0].entity_id == "web01"

    def test_fires_when_apparmor_stopped(self):
        rule = SecurityControlDisabledRule()
        assert len(rule.analyze([rec(1, process="systemd", message="Stopping apparmor...")])) == 1

    def test_near_miss_ordinary_service_stopped_does_not_fire(self):
        # Routine: an admin restarting a web server.
        rule = SecurityControlDisabledRule()
        assert rule.analyze([rec(1, process="systemd", message="Stopped A high performance web server and a reverse proxy server (nginx).")]) == []

    def test_near_miss_security_service_started_does_not_fire(self):
        rule = SecurityControlDisabledRule()
        assert rule.analyze([rec(1, process="systemd", message="Started fail2ban.")]) == []

    def test_configured_allowlist_replaces_default_watch_list(self):
        rule = SecurityControlDisabledRule(allowlist=["crowdstrike"])
        records = [
            rec(1, process="systemd", message="Stopped crowdstrike-falcon-sensor."),
            rec(2, process="systemd", message="Stopped fail2ban."),
        ]
        alerts = rule.analyze(records)
        assert len(alerts) == 1
        assert "crowdstrike" in alerts[0].description

    def test_end_to_end_through_syslog_parser(self):
        line = "Jun 14 02:11:00 web01 systemd[1]: Stopped fail2ban."
        entry = parse_syslog("", [line])["entries"][0]["parsed"]
        record = LogRecord(
            line_number=1, timestamp=entry["timestamp"], hostname=entry["hostname"],
            process=entry["process"], message=entry["message"],
        )
        assert len(SecurityControlDisabledRule().analyze([record])) == 1
