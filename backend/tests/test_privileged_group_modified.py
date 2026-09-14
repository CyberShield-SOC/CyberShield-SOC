import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

pytestmark = pytest.mark.no_db

from app.detection.models import LogRecord
from app.detection.rules.privileged_group_modified import PrivilegedGroupModifiedRule
from app.parsers.syslog_parser import parse_syslog


def rec(n, process=None, message=None, hostname="web01", ts="2026-06-14T02:11:00Z"):
    return LogRecord(
        line_number=n, timestamp=ts, hostname=hostname, process=process, message=message,
    )


class TestPrivilegedGroupModifiedRule:
    def test_fires_on_usermod_add_to_sudo(self):
        rule = PrivilegedGroupModifiedRule()
        records = [rec(1, process="usermod", message="add 'mallory' to group 'sudo'")]
        alerts = rule.analyze(records)
        assert len(alerts) == 1
        assert alerts[0].username == "mallory"
        assert "sudo" in alerts[0].description
        assert alerts[0].mitre_technique == "T1098"

    def test_fires_on_gpasswd_add_to_wheel(self):
        rule = PrivilegedGroupModifiedRule()
        records = [rec(1, process="gpasswd", message="user mallory added by root to group wheel")]
        alerts = rule.analyze(records)
        assert len(alerts) == 1
        assert alerts[0].username == "mallory"

    def test_near_miss_non_privileged_group_does_not_fire(self):
        # Routine admin activity: adding someone to an ordinary group.
        rule = PrivilegedGroupModifiedRule()
        records = [rec(1, process="usermod", message="add 'alice' to group 'developers'")]
        assert rule.analyze(records) == []

    def test_configured_allowlist_overrides_default_groups(self):
        rule = PrivilegedGroupModifiedRule(allowlist=["developers"])
        records = [
            rec(1, process="usermod", message="add 'alice' to group 'developers'"),
            rec(2, process="usermod", message="add 'bob' to group 'sudo'"),
        ]
        alerts = rule.analyze(records)
        assert [a.username for a in alerts] == ["alice"]

    def test_end_to_end_through_syslog_parser(self):
        line = "Jun 14 02:11:00 web01 usermod[4099]: add 'mallory' to group 'sudo'"
        entry = parse_syslog("", [line])["entries"][0]["parsed"]
        record = LogRecord(
            line_number=1, timestamp=entry["timestamp"], hostname=entry["hostname"],
            process=entry["process"], message=entry["message"],
        )
        alerts = PrivilegedGroupModifiedRule().analyze([record])
        assert len(alerts) == 1
        assert alerts[0].username == "mallory"
