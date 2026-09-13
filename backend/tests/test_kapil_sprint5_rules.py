from pathlib import Path

import pytest

from app.detection.engine import DetectionEngine
from app.detection.models import LogRecord
from app.parsers.log_parser import parse_log

pytestmark = pytest.mark.no_db

SAMPLES = Path(__file__).resolve().parents[2] / "sample-logs"


def load_sample(name):
    content = (SAMPLES / name).read_text(encoding="utf-8")
    parsed = parse_log(content, name)
    assert parsed["skipped_lines"] == []
    return [LogRecord(line_number=entry["line_number"], **entry["parsed"]) for entry in parsed["entries"]]


def test_suspicious_sample_triggers_both_new_rules():
    alerts = DetectionEngine().run(load_sample("kk_suspicious.csv"))
    by_rule = {alert.rule: alert for alert in alerts}
    assert by_rule["multi_ip_successful_login"].matched_line_numbers == [2, 3, 4]
    assert by_rule["sudo_after_login"].matched_line_numbers == [5, 6]


def test_normal_sample_does_not_trigger_new_rules():
    alerts = DetectionEngine().run(load_sample("kk_normal.csv"))
    assert not {"multi_ip_successful_login", "sudo_after_login"} & {alert.rule for alert in alerts}


def test_rule_configuration_and_account_isolation():
    engine = DetectionEngine.from_config({
        "multi_ip_successful_login": {"threshold": 2},
        "sudo_after_login": {"enabled": False},
    })
    alerts = engine.run(load_sample("kk_suspicious.csv"))
    assert "multi_ip_successful_login" in {alert.rule for alert in alerts}
    assert "sudo_after_login" not in {alert.rule for alert in alerts}
    assert next(rule for rule in engine.rule_metadata() if rule.name == "multi_ip_successful_login").config.threshold == 2
