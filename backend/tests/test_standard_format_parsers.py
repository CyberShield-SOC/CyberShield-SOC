"""CEF, LEEF, and RFC 3164/5424 syslog: parsing, auto-detection, detection."""

from __future__ import annotations

import sys
from io import BytesIO
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, select

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.detection.normalize import log_record_from_entry
from app.detection.rules.brute_force import BruteForceLoginRule
from app.main import app
from app.models.detection_rule_setting import DetectionRuleSetting
from app.models.role import Role
from app.models.user import User
from app.parsers.cef_parser import parse_cef_log
from app.parsers.leef_parser import parse_leef_log
from app.parsers.log_parser import parse_log
from app.parsers.siem_common import (
    parse_space_separated_attributes,
    severity_from_scale,
    timestamp_from_siem,
)
from app.parsers.syslog_parser import parse_syslog
from app.security import current_user


pytestmark = pytest.mark.no_db

SAMPLES = Path(__file__).resolve().parents[2] / "sample-logs"


def load(name: str) -> dict:
    return parse_log((SAMPLES / name).read_text(encoding="utf-8"), name)


def records(parsed: dict) -> list:
    return [log_record_from_entry(entry, parsed["format"]) for entry in parsed["entries"]]


def parse_lines(parser, *lines: str) -> dict:
    return parser("\n".join(lines), list(lines))


# --- shared helpers --------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("0", "LOW"), ("3", "LOW"), ("4", "MEDIUM"), ("6", "MEDIUM"),
        ("7", "HIGH"), ("8", "HIGH"), ("9", "CRITICAL"), ("10", "CRITICAL"),
        ("Low", "LOW"), ("Very-High", "CRITICAL"), ("Unknown", None),
        ("11", None), ("", None), ("severe", None),
    ],
)
def test_severity_scale_follows_the_cef_bands(value, expected):
    assert severity_from_scale(value) == expected


def test_siem_timestamps_become_iso_and_unknown_text_is_kept():
    assert timestamp_from_siem("1767859201000") == "2026-01-08T08:00:01Z"
    assert timestamp_from_siem("1767859201") == "2026-01-08T08:00:01Z"
    assert timestamp_from_siem("Jan 10 2026 08:00:01") == "2026-01-10T08:00:01Z"
    assert timestamp_from_siem("Jan 10 2026 08:00:01 UTC") == "2026-01-10T08:00:01Z"
    assert timestamp_from_siem("2026-01-10 08:00:01.250") == "2026-01-10T08:00:01.250000Z"
    assert timestamp_from_siem("next tuesday") == "next tuesday"
    assert timestamp_from_siem("") is None


def test_space_separated_values_keep_their_spaces_and_escaped_equals():
    attributes = parse_space_separated_attributes(
        r"src=10.0.0.1 msg=Blocked by policy \= default deny act=blocked filePath=C:\\Temp\\a b.exe"
    )

    assert attributes == {
        "src": "10.0.0.1",
        "msg": "Blocked by policy = default deny",
        "act": "blocked",
        "filePath": r"C:\Temp\a b.exe",
    }


# --- CEF -------------------------------------------------------------------


def test_cef_fixture_is_detected_and_fully_parsed():
    parsed = load("cef_bruteforce.log")

    assert parsed["format"] == "cef"
    assert len(parsed["entries"]) == 8
    assert [(line["line_number"], line["reason"]) for line in parsed["skipped_lines"]] == [(1, "comment")]

    failed = parsed["entries"][0]["parsed"]
    assert failed["timestamp"] == "2026-01-10T08:00:01Z"
    assert failed["ip_address"] == "203.0.113.50"
    assert failed["username"] == "root"
    assert failed["event_type"] == "login_attempt"
    assert failed["status"] == "FAILED"
    assert failed["severity"] == "MEDIUM"
    assert failed["hostname"] == "fw01"
    assert failed["dest_ip"] == "10.0.0.5"
    assert failed["protocol"] == "TCP"
    assert failed["message"] == "Failed password for root"
    assert failed["cef"]["device_vendor"] == "Acme"
    assert failed["cef"]["signature_id"] == "100"


def test_cef_fields_reach_the_detection_record():
    parsed = load("cef_bruteforce.log")
    blocked = records(parsed)[-1]

    assert blocked.ip_address == "10.0.0.9"
    assert blocked.dest_ip == "203.0.113.200"
    assert blocked.port == 4444
    assert blocked.bytes_in == 120
    assert blocked.bytes_out == 98000
    assert blocked.status == "FAILED"
    assert blocked.message == "Blocked by policy = default deny"
    assert parsed["entries"][-1]["parsed"]["severity"] == "HIGH"
    assert parsed["entries"][-1]["parsed"]["cef"]["labels"] == {"Policy": "egress-default-deny"}


def test_cef_brute_force_fires_and_the_success_does_not_count():
    alerts = BruteForceLoginRule().analyze(records(load("cef_bruteforce.log")))

    assert {alert.source_ip for alert in alerts} == {"203.0.113.50"}


def test_cef_header_escapes_and_bare_records_without_a_syslog_carrier():
    parsed = parse_lines(
        parse_cef_log,
        r"CEF:0|Acme\|Corp|Shield\\Pro|1.0|42|Pipe \| in name|10|suser=alice duser=root dvchost=host9",
    )
    entry = parsed["entries"][0]["parsed"]

    assert entry["cef"]["device_vendor"] == "Acme|Corp"
    assert entry["cef"]["device_product"] == r"Shield\Pro"
    assert entry["cef"]["name"] == "Pipe | in name"
    assert entry["severity"] == "CRITICAL"
    assert entry["hostname"] == "host9"
    # Not a sign-in, so the acting (source) user is the account of interest.
    assert entry["username"] == "alice"
    assert entry["timestamp"] is None


def test_cef_uses_the_syslog_carrier_when_the_event_states_no_time_or_host():
    parsed = parse_lines(
        parse_cef_log,
        "<131>1 2026-03-02T11:22:33Z edge7 cef - - - CEF:0|Acme|GW|1|7|Scan|Unknown|src=10.1.1.1",
    )
    entry = parsed["entries"][0]["parsed"]

    assert entry["timestamp"] == "2026-03-02T11:22:33Z"
    assert entry["hostname"] == "edge7"
    # CEF says "Unknown", so the carrier's syslog severity (3 = error) stands.
    assert entry["severity"] == "ERROR"


def test_cef_lines_that_are_not_cef_are_skipped_with_a_reason():
    parsed = parse_lines(
        parse_cef_log,
        "CEF:0|Acme|GW|1|7|Scan|3|src=10.1.1.1",
        "Jan 10 08:00:01 fw01 kernel: unrelated line",
        "CEF:0|Acme|GW|truncated",
        "#4821 CEF:0|Acme|GW|1|7|Ticket-prefixed|3|src=10.1.1.2",
    )

    assert [entry["line_number"] for entry in parsed["entries"]] == [1, 4]
    assert [(line["line_number"], line["reason"]) for line in parsed["skipped_lines"]] == [
        (2, "Not a CEF record"),
        (3, "Incomplete CEF header"),
    ]


# --- LEEF ------------------------------------------------------------------


def test_leef_fixture_parses_both_versions():
    parsed = load("leef_bruteforce.log")

    assert parsed["format"] == "leef"
    assert len(parsed["entries"]) == 7
    assert [line["reason"] for line in parsed["skipped_lines"]] == ["comment"]

    v1 = parsed["entries"][0]["parsed"]
    assert v1["timestamp"] == "2026-01-10T09:00:01Z"
    assert v1["ip_address"] == "203.0.113.51"
    assert v1["username"] == "root"
    assert v1["event_type"] == "login_attempt"
    assert v1["status"] == "FAILED"
    assert v1["severity"] == "MEDIUM"
    assert v1["hostname"] == "qradar01"
    assert v1["leef"] == {
        "version": "1.0",
        "vendor": "Acme",
        "product": "AuthGateway",
        "product_version": "2.1",
        "event_id": "LOGIN_FAILED",
    }

    v2 = parsed["entries"][-1]["parsed"]
    assert v2["leef"]["version"] == "2.0"
    assert v2["ip_address"] == "198.51.100.8"
    assert v2["username"] == "bob"
    assert v2["status"] == "SUCCESS"
    assert v2["severity"] == "LOW"
    assert records(parsed)[-1].port == 22


def test_leef_brute_force_fires():
    alerts = BruteForceLoginRule().analyze(records(load("leef_bruteforce.log")))

    assert {alert.source_ip for alert in alerts} == {"203.0.113.51"}


@pytest.mark.parametrize(
    "line",
    [
        "LEEF:2.0|Acme|GW|1|EVT|0x09|src=10.2.2.2\tusrName=eve\tsev=9",
        "LEEF:2.0|Acme|GW|1|EVT|x7c|src=10.2.2.2|usrName=eve|sev=9",
        "LEEF:2.0|Acme|GW|1|EVT|src=10.2.2.2\tusrName=eve\tsev=9",
        "LEEF:1.0|Acme|GW|1|EVT|src=10.2.2.2 usrName=eve sev=9",
    ],
    ids=["hex-tab", "hex-pipe", "no-delimiter-field", "tabs-flattened-to-spaces"],
)
def test_leef_delimiter_variants(line):
    entry = parse_lines(parse_leef_log, line)["entries"][0]["parsed"]

    assert entry["ip_address"] == "10.2.2.2"
    assert entry["username"] == "eve"
    assert entry["severity"] == "CRITICAL"


def test_leef_byte_counts_map_source_sent_to_bytes_out():
    parsed = parse_lines(
        parse_leef_log,
        "LEEF:1.0|Acme|GW|1|FLOW|src=10.0.0.9\tdst=203.0.113.9\tsrcBytes=5000\tdstBytes=70",
    )
    record = records(parsed)[0]

    assert (record.bytes_out, record.bytes_in) == (5000, 70)


# --- syslog: PRI and RFC 5424 ----------------------------------------------


def test_rfc5424_fixture_is_detected_and_parsed():
    parsed = load("rfc5424_bruteforce.log")

    assert parsed["format"] == "syslog_rfc5424"
    assert parsed["skipped_lines"] == []
    assert len(parsed["entries"]) == 8

    failed = parsed["entries"][0]["parsed"]
    assert failed["timestamp"] == "2026-01-10T10:00:01.000Z"
    assert failed["hostname"] == "server02"
    assert failed["process"] == "sshd"
    assert failed["pid"] == 2100
    assert failed["ip_address"] == "203.0.113.52"
    assert failed["username"] == "root"
    assert failed["event_type"] == "login_attempt"
    assert failed["status"] == "FAILED"
    assert (failed["syslog_facility"], failed["syslog_severity"]) == (4, 6)
    # auth.info on the wire, but the text says "Failed": the stronger wins.
    assert failed["severity"] == "WARNING"


def test_rfc5424_structured_data_is_parsed_with_escapes():
    entry = load("rfc5424_bruteforce.log")["entries"][6]["parsed"]

    assert entry["msgid"] == "ID47"
    assert entry["structured_data"] == {
        "origin@32473": {"ip": "198.51.100.9", "user": "carol"},
        "meta@32473": {"note": 'quoted "value" with ] bracket'},
    }
    assert entry["ip_address"] == "198.51.100.9"
    assert entry["username"] == "carol"
    assert entry["status"] == "SUCCESS"
    assert entry["message"].startswith("Accepted publickey for carol")


def test_rfc5424_nil_fields_and_sudo_structure():
    entry = load("rfc5424_bruteforce.log")["entries"][7]["parsed"]

    assert entry["pid"] is None
    assert entry["msgid"] is None
    assert "structured_data" not in entry
    assert entry["process"] == "sudo"
    assert entry["command"] == "/usr/bin/id"
    assert entry["severity"] == "INFO"


def test_rfc5424_brute_force_fires():
    alerts = BruteForceLoginRule().analyze(records(load("rfc5424_bruteforce.log")))

    assert {alert.source_ip for alert in alerts} == {"203.0.113.52"}


def test_rfc3164_with_a_priority_prefix_now_parses():
    line = "<34>Jan 10 08:00:01 server01 sshd[1234]: Failed password for root from 203.0.113.4 port 22 ssh2"
    parsed = parse_log(line, "auth.log")
    entry = parsed["entries"][0]["parsed"]

    assert parsed["format"] == "syslog"
    assert parsed["skipped_lines"] == []
    assert entry["hostname"] == "server01"
    assert entry["ip_address"] == "203.0.113.4"
    assert (entry["syslog_facility"], entry["syslog_severity"]) == (4, 2)
    assert entry["severity"] == "CRITICAL"


def test_plain_rfc3164_lines_are_unchanged_by_priority_support():
    line = "Jan 10 08:00:01 server01 sshd[1234]: Failed password for root from 203.0.113.4 port 22 ssh2"
    entry = parse_lines(parse_syslog, line)["entries"][0]["parsed"]

    assert entry["severity"] == "WARNING"
    assert "syslog_facility" not in entry
    assert "msgid" not in entry


@pytest.mark.parametrize(
    "line",
    [
        "<999>Jan 10 08:00:01 server01 sshd[1]: out-of-range priority",
        '<34>1 2026-01-10T08:00:01Z host app - - [bad sd="unterminated] message',
        "<34>1 2026-01-10T08:00:01Z host app - - no-structured-data-marker message",
    ],
    ids=["priority-over-191", "unterminated-sd-value", "missing-sd"],
)
def test_malformed_syslog_is_skipped_not_guessed(line):
    parsed = parse_lines(parse_syslog, line)

    assert parsed["entries"] == []
    assert len(parsed["skipped_lines"]) == 1


def test_a_txt_file_of_cef_is_not_mistaken_for_a_pipe_delimited_table():
    content = (SAMPLES / "cef_bruteforce.log").read_text(encoding="utf-8")

    assert parse_log(content, "export.txt")["format"] == "cef"


# --- end to end ------------------------------------------------------------


@pytest.mark.db
@pytest.mark.parametrize(
    ("fixture", "expected_format", "attacker"),
    [
        ("cef_bruteforce.log", "cef", "203.0.113.50"),
        ("leef_bruteforce.log", "leef", "203.0.113.51"),
        ("rfc5424_bruteforce.log", "syslog_rfc5424", "203.0.113.52"),
    ],
)
def test_uploading_each_format_stores_events_and_raises_the_brute_force_alert(
    fixture, expected_format, attacker, db_session
):
    role = db_session.scalar(select(Role).where(Role.name == "Admin"))
    if role is None:
        role = Role(name="Admin", description="Admin test role")
        db_session.add(role)
        db_session.flush()
    suffix = uuid4().hex[:8]
    admin = User(role_id=role.id, username=f"format-{suffix}", email=f"format-{suffix}@example.test",
                 password_hash="unused", is_active=True)
    db_session.add(admin)
    # A saved brute-force override from manual use must not decide this test.
    db_session.execute(delete(DetectionRuleSetting))
    db_session.commit()
    admin.role = role
    app.dependency_overrides[current_user] = lambda: admin
    try:
        response = TestClient(app).post(
            "/upload",
            files={"logfile": (fixture, BytesIO((SAMPLES / fixture).read_bytes()), "text/plain")},
        )
    finally:
        app.dependency_overrides.pop(current_user, None)

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["parsing"]["format"] == expected_format
    assert body["parsing"]["stored_entries"] == body["parsing"]["parsed_entries"] > 0
    brute_force = [alert for alert in body["alerts"] if alert["rule"] == "brute_force_login"]
    assert [alert["source_ip"] for alert in brute_force] == [attacker]
