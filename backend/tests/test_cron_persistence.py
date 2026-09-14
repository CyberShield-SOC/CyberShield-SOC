import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

pytestmark = pytest.mark.no_db

from app.detection.models import LogRecord
from app.detection.rules.cron_persistence import CronPersistenceRule
from app.parsers.syslog_parser import parse_syslog


def rec(n, process=None, message=None, hostname="web01", ts="2026-06-14T02:11:00Z"):
    return LogRecord(
        line_number=n, timestamp=ts, hostname=hostname, process=process, message=message,
    )


class TestCronPersistenceRule:
    def test_fires_on_crontab_replace(self):
        rule = CronPersistenceRule()
        alerts = rule.analyze([rec(1, process="crontab", message="(mallory) REPLACE (mallory)")])
        assert len(alerts) == 1
        assert alerts[0].severity == "MEDIUM"
        assert alerts[0].mitre_technique == "T1053.003"
        assert "mallory" in alerts[0].description

    def test_fires_on_systemd_timer_started(self):
        rule = CronPersistenceRule()
        alerts = rule.analyze([rec(1, process="systemd", message="Started backdoor.timer.")])
        assert len(alerts) == 1
        assert "backdoor.timer" in alerts[0].description

    def test_near_miss_routine_cron_execution_does_not_fire(self):
        # CRON *running* an existing job is routine and must not be flagged —
        # only creating/editing an entry is a persistence signal.
        rule = CronPersistenceRule()
        records = [rec(1, process="CRON", message="(root) CMD (run-parts /etc/cron.hourly)")]
        assert rule.analyze(records) == []

    def test_near_miss_crontab_list_does_not_fire(self):
        # `crontab -l` only reads — no persistence was created.
        rule = CronPersistenceRule()
        assert rule.analyze([rec(1, process="crontab", message="(alice) LIST (alice)")]) == []

    def test_near_miss_systemd_non_timer_unit_does_not_fire(self):
        rule = CronPersistenceRule()
        assert rule.analyze([rec(1, process="systemd", message="Started nginx.service.")]) == []

    def test_end_to_end_through_syslog_parser(self):
        line = "Jun 14 02:11:00 web01 crontab[5120]: (mallory) REPLACE (mallory)"
        entry = parse_syslog("", [line])["entries"][0]["parsed"]
        record = LogRecord(
            line_number=1, timestamp=entry["timestamp"], hostname=entry["hostname"],
            process=entry["process"], message=entry["message"],
        )
        assert len(CronPersistenceRule().analyze([record])) == 1
