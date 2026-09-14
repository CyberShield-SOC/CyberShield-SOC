import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

pytestmark = pytest.mark.no_db

from app.detection.models import LogRecord
from app.detection.rules.new_account_created import NewAccountCreatedRule
from app.parsers.syslog_parser import parse_syslog


def rec(n, process=None, message=None, hostname="web01", ts="2026-06-14T02:11:00Z"):
    return LogRecord(
        line_number=n, timestamp=ts, hostname=hostname, process=process, message=message,
    )


class TestNewAccountCreatedRule:
    def test_fires_on_useradd(self):
        rule = NewAccountCreatedRule()
        records = [rec(1, process="useradd", message="new user: name=mallory, UID=1010, GID=1010, home=/home/mallory, shell=/bin/bash")]
        alerts = rule.analyze(records)
        assert len(alerts) == 1
        assert alerts[0].rule == "new_account_created"
        assert alerts[0].username == "mallory"
        assert alerts[0].entity_type == "host"
        assert alerts[0].entity_id == "web01"
        assert alerts[0].mitre_technique == "T1136"

    def test_fires_on_adduser_wrapper(self):
        rule = NewAccountCreatedRule()
        records = [rec(1, process="adduser", message="Adding user `bob' ...")]
        alerts = rule.analyze(records)
        assert len(alerts) == 1
        assert alerts[0].username == "bob"

    def test_near_miss_unrelated_process_does_not_fire(self):
        # Same host, plausible-looking message, but not from useradd/adduser —
        # e.g. a user merely mentioning "new user" in an unrelated context.
        rule = NewAccountCreatedRule()
        records = [rec(1, process="sshd", message="Accepted password for mallory from 10.0.0.5 port 51000 ssh2")]
        assert rule.analyze(records) == []

    def test_near_miss_no_process_field_does_not_fire(self):
        # Non-syslog sources never populate `process` — must fail safe, not guess.
        rule = NewAccountCreatedRule()
        records = [rec(1, process=None, message="new user: name=mallory")]
        assert rule.analyze(records) == []

    def test_end_to_end_through_syslog_parser(self):
        """Proves the hostname/process/message plumbing actually works, not
        just the rule's own filtering logic."""

        line = "Jun 14 02:11:00 web01 useradd[4021]: new user: name=mallory, UID=1010, GID=1010, home=/home/mallory, shell=/bin/bash"
        parsed = parse_syslog("", [line])
        entry = parsed["entries"][0]["parsed"]
        record = LogRecord(
            line_number=1,
            timestamp=entry["timestamp"],
            hostname=entry["hostname"],
            process=entry["process"],
            message=entry["message"],
        )
        alerts = NewAccountCreatedRule().analyze([record])
        assert len(alerts) == 1
        assert alerts[0].username == "mallory"
        assert alerts[0].hostname == "web01"
