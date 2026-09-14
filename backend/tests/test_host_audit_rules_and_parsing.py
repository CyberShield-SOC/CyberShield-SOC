"""ssh_key_added, host_log_silence, the auditd parser, structured syslog
extraction, and the LogRecord normalizer."""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.detection.normalize import log_record_from_entry
from app.detection.models import LogRecord
from app.detection.rules.host_log_silence import HostLogSilenceRule
from app.detection.rules.ssh_key_added import SshKeyAddedRule
from app.parsers.auditd_parser import parse_auditd_log
from app.parsers.log_parser import parse_log
from app.parsers.structured_fields import extract_from_message
from app.parsers.syslog_parser import parse_syslog


def audit_records(lines: list[str]) -> list[LogRecord]:
    parsed = parse_auditd_log("\n".join(lines), lines)
    return [log_record_from_entry(entry, parsed["format"]) for entry in parsed["entries"]]


def syslog_records(lines: list[str]) -> list[LogRecord]:
    parsed = parse_syslog("\n".join(lines), lines)
    return [log_record_from_entry(entry, parsed["format"]) for entry in parsed["entries"]]


WRITE_EVENT = [
    'node=app01 type=SYSCALL msg=audit(1789050600.100:1): arch=c000003e syscall=257 success=yes a0=ffffff9c a1=1 a2=441 a3=1b6 items=2 auid=1003 uid=0 comm="bash" exe="/usr/bin/bash" key="ssh_keys" AUID="mallory"',
    'node=app01 type=PATH msg=audit(1789050600.100:1): item=0 name="/root/.ssh/" nametype=PARENT',
    'node=app01 type=PATH msg=audit(1789050600.100:1): item=1 name="/root/.ssh/authorized_keys" nametype=NORMAL',
]
READ_EVENT = [
    'node=app01 type=SYSCALL msg=audit(1789050610.100:2): arch=c000003e syscall=257 success=yes a0=ffffff9c a1=1 a2=0 a3=0 items=1 auid=4294967295 uid=0 comm="sshd" exe="/usr/sbin/sshd" key="ssh_keys"',
    'node=app01 type=PATH msg=audit(1789050610.100:2): item=0 name="/root/.ssh/authorized_keys" nametype=NORMAL',
]


# ── auditd parser ────────────────────────────────────────────────────────────

@pytest.mark.no_db
class TestAuditdParser:
    def test_records_merge_into_one_event(self):
        parsed = parse_auditd_log("", WRITE_EVENT + READ_EVENT)
        assert parsed["format"] == "auditd"
        assert len(parsed["entries"]) == 2
        first = parsed["entries"][0]["parsed"]
        assert first["file_path"] == "/root/.ssh/authorized_keys"
        assert first["username"] == "mallory"
        assert first["hostname"] == "app01"
        assert first["timestamp"].startswith("2026-09-10T14:30:00")
        assert first["audit_fields"]["syscall"] == "257"

    def test_hex_encoded_execve_arguments_are_decoded(self):
        lines = ['type=EXECVE msg=audit(1789050600.1:9): argc=3 a0="bash" a1="-c" a2=686973746F7279202D63']
        assert parse_auditd_log("", lines)["entries"][0]["parsed"]["command"] == "bash -c history -c"

    def test_log_parser_auto_detects_audit_content(self):
        assert parse_log("\n".join(WRITE_EVENT), "audit.log")["format"] == "auditd"


# ── ssh_key_added ───────────────────────────────────────────────────────────

@pytest.mark.no_db
class TestSshKeyAdded:
    def test_write_mode_open_on_authorized_keys_fires(self):
        alerts = SshKeyAddedRule().analyze(audit_records(WRITE_EVENT))
        assert len(alerts) == 1
        assert alerts[0].username == "mallory"
        assert alerts[0].mitre_technique == "T1098.004"

    def test_near_miss_sshd_reading_keys(self):
        assert SshKeyAddedRule().analyze(audit_records(READ_EVENT)) == []

    def test_sudo_command_writing_keys_fires(self):
        records = syslog_records([
            "Sep 10 14:03:00 web01 sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/tee -a /root/.ssh/authorized_keys",
        ])
        alerts = SshKeyAddedRule().analyze(records)
        assert len(alerts) == 1
        assert alerts[0].evidence["file_path"] == "/root/.ssh/authorized_keys"

    def test_near_miss_sudo_cat_keys(self):
        records = syslog_records([
            "Sep 10 14:03:00 web01 sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/cat /root/.ssh/authorized_keys",
        ])
        assert SshKeyAddedRule().analyze(records) == []

    def test_audit_forwarded_through_syslog_is_correlated(self):
        lines = [f"Sep 10 14:30:00 app01 audit: {line.split(' ', 1)[1]}" for line in WRITE_EVENT]
        alerts = SshKeyAddedRule().analyze(syslog_records(lines))
        assert len(alerts) == 1
        assert alerts[0].matched_line_numbers == [1, 2, 3]

    def test_create_nametype_fires_even_without_watch_key(self):
        lines = [
            'type=SYSCALL msg=audit(1789050600.1:5): arch=c000003e syscall=82 success=yes items=2 comm="mv" exe="/usr/bin/mv" key=(null)',
            'type=PATH msg=audit(1789050600.1:5): item=1 name="/home/bob/.ssh/authorized_keys" nametype=CREATE',
        ]
        assert len(SshKeyAddedRule().analyze(audit_records(lines))) == 1


# ── host_log_silence ─────────────────────────────────────────────────────────

BASE = datetime(2026, 9, 10, 9, 0, tzinfo=timezone.utc)


def beat(n, host, minute):
    return LogRecord(line_number=n, hostname=host, timestamp=(BASE + timedelta(minutes=minute)).strftime("%Y-%m-%dT%H:%M:%SZ"))


class TestHostLogSilence:
    @pytest.mark.no_db
    def test_gap_inside_one_upload_fires_and_resumes(self):
        records = [beat(i, "db02", i) for i in range(30)] + [beat(100, "db02", 120)]
        alerts = HostLogSilenceRule().analyze(records)
        assert len(alerts) == 1
        assert alerts[0].evidence["ongoing"] is False
        assert alerts[0].evidence["silence_seconds"] == 91 * 60

    @pytest.mark.no_db
    def test_host_quiet_while_others_keep_reporting(self):
        records = [beat(i, "web03", i) for i in range(120)] + [beat(1000 + i, "cache01", i) for i in range(40)]
        alerts = HostLogSilenceRule().analyze(records)
        assert [a.entity_id for a in alerts] == ["cache01"]
        assert alerts[0].evidence["ongoing"] is True

    @pytest.mark.no_db
    def test_near_miss_host_without_established_cadence(self):
        records = [beat(i, "new01", i) for i in range(5)] + [beat(10, "new01", 300)]
        assert HostLogSilenceRule().analyze(records) == []

    @pytest.mark.no_db
    def test_near_miss_gap_below_floor(self):
        records = [beat(i, "db02", i) for i in range(30)] + [beat(100, "db02", 50)]
        assert HostLogSilenceRule().analyze(records) == []

    def test_silence_across_uploads_alerts_once_per_episode(self, db_session):
        host = f"h-{uuid4().hex[:6]}"
        other = f"o-{uuid4().hex[:6]}"
        rule = HostLogSilenceRule()
        assert rule.analyze([beat(i, host, i) for i in range(30)], db_session) == []
        later = [beat(i, other, 100 + i) for i in range(5)]
        first = rule.analyze(later, db_session)
        assert [a.entity_id for a in first if a.entity_id == host] == [host]
        assert [a for a in rule.analyze(later, db_session) if a.entity_id == host] == []

    def test_check_endpoint_uses_wall_clock(self, db_session):
        from fastapi.testclient import TestClient
        from sqlalchemy import select

        from app.main import app
        from app.models.role import Role
        from app.models.user import User
        from app.security import current_user

        role = db_session.scalar(select(Role).where(Role.name == "Analyst")) or Role(name="Analyst", description="t")
        db_session.add(role)
        db_session.flush()
        user = User(role_id=role.id, username=f"a-{uuid4().hex[:6]}", email=f"{uuid4().hex[:6]}@example.test", password_hash="x", is_active=True)
        user.role = role
        db_session.add(user)
        host = f"old-{uuid4().hex[:6]}"
        HostLogSilenceRule().analyze([beat(i, host, i) for i in range(30)], db_session)
        db_session.commit()

        app.dependency_overrides[current_user] = lambda: user
        try:
            client = TestClient(app)
            response = client.post("/detection/host-silence/check")
            assert response.status_code == 200
            assert host in {a["entity_id"] for a in response.json()["alerts"]}
            hosts = {h["hostname"]: h for h in client.get("/detection/host-heartbeats").json()["hosts"]}
            assert hosts[host]["status"] == "silent"
            again = client.post("/detection/host-silence/check").json()["alerts"]
            assert host not in {a["entity_id"] for a in again}
        finally:
            app.dependency_overrides.pop(current_user, None)


# ── structured syslog extraction & normalizer ───────────────────────────────

@pytest.mark.no_db
class TestStructuredExtraction:
    def test_ufw_block_line(self):
        fields = extract_from_message("kernel", "[123.4] [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.7 DST=10.0.0.5 LEN=60 PROTO=TCP SPT=4444 DPT=22")
        assert fields["ip_address"] == "203.0.113.7"
        assert fields["dest_ip"] == "10.0.0.5"
        assert fields["destination_port"] == 22
        assert fields["status"] == "FAILED"
        assert "bytes_out" not in fields

    def test_dnsmasq_bind_and_unbound_queries(self):
        assert extract_from_message("dnsmasq", "query[TXT] abc.example.com from 10.0.5.23")["dns_query"] == "abc.example.com"
        bind = extract_from_message("named", "client @0x7f 10.0.5.9#53001 (x.example.org): query: x.example.org IN A +E(0)")
        assert (bind["ip_address"], bind["dns_query_type"]) == ("10.0.5.9", "A")
        assert extract_from_message("unbound", "info: 10.0.5.8 y.example.net. AAAA IN")["dns_query"] == "y.example.net"

    def test_non_matching_messages_extract_nothing(self):
        assert extract_from_message("sshd", "Accepted publickey for alice from 10.0.0.1 port 22 ssh2") == {}

    def test_publickey_logins_are_login_attempts(self):
        record = syslog_records(["Sep 10 14:05:00 bastion01 sshd[1]: Accepted publickey for root from 198.51.100.23 port 51122 ssh2"])[0]
        assert (record.event_type, record.status, record.username) == ("login_attempt", "SUCCESS", "root")


@pytest.mark.no_db
class TestNormalizer:
    def test_ecs_style_json_maps_network_dns_and_geo(self):
        content = (
            '{"@timestamp":"2026-09-10T14:00:00Z","source":{"ip":"73.12.44.9","geo":{"country_iso_code":"us",'
            '"location":{"lat":40.7,"lon":-74.0}},"as":{"number":7922},"bytes":1234},'
            '"destination":{"ip":"45.33.32.156","port":8443},"dns":{"question":{"name":"Evil.Example.com.","type":"TXT"}},'
            '"host":{"name":"ws-114"},"event":{"action":"connection"}}'
        )
        parsed = parse_log(content, "events.json")
        record = log_record_from_entry(parsed["entries"][0], parsed["format"])
        assert record.ip_address == "73.12.44.9"
        assert (record.dest_ip, record.port, record.bytes_out) == ("45.33.32.156", 8443, 1234)
        assert (record.country, record.asn, record.latitude) == ("US", "7922", 40.7)
        assert record.dns_query == "evil.example.com"
        assert record.hostname == "ws-114"

    def test_csv_columns_and_bad_values_are_dropped_not_fatal(self):
        content = "timestamp,hostname,src_ip,dst_ip,dest_port,bytes_sent,lat\n2026-09-10T14:00:00Z,fs-02,10.0.4.2,not-an-ip,443,12a,999\n"
        parsed = parse_log(content, "flows.csv")
        record = log_record_from_entry(parsed["entries"][0], parsed["format"])
        assert record.hostname == "fs-02" and record.port == 443
        assert record.dest_ip is None and record.bytes_out is None and record.latitude is None

    def test_apache_url_path_is_not_a_file_path(self):
        line = '1.2.3.4 - - [10/Sep/2026:14:00:00 +0000] "GET /home/.ssh/authorized_keys HTTP/1.1" 404 12'
        parsed = parse_log(line, "access.log")
        assert log_record_from_entry(parsed["entries"][0], parsed["format"]).file_path is None
