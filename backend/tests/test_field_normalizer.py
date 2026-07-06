import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.parsers.field_normalizer import (  # noqa: E402
    first_ip,
    normalize_entry,
    status_from_text,
    username_from_text,
)


def test_normalize_entry_canonicalizes_core_fields():
    entry = normalize_entry(
        timestamp=" 2026-07-06T12:00:00Z ",
        ip_address="203.0.113.4",
        username=" admin ",
        event_type="Login Success",
        status="success",
    )

    assert entry == {
        "timestamp": "2026-07-06T12:00:00Z",
        "ip_address": "203.0.113.4",
        "username": "admin",
        "event_type": "login_success",
        "status": "SUCCESS",
    }


def test_normalize_entry_rejects_invalid_ip_and_defaults_missing_values():
    entry = normalize_entry(ip_address="999.999.999.999", event_type="", status=None)

    assert entry["ip_address"] is None
    assert entry["event_type"] == "security_event"
    assert entry["status"] == "UNKNOWN"


def test_first_ip_uses_valid_ipv4_octets():
    assert first_ip("connection from 10.0.0.7 port 22") == "10.0.0.7"
    assert first_ip("connection from 999.999.999.999 port 22") is None


def test_status_from_text_detects_common_outcomes():
    assert status_from_text("request rejected by policy") == "FAILED"
    assert status_from_text("health check passed") == "SUCCESS"
    assert status_from_text("service started") == "INFO"


def test_username_from_text_detects_more_formats():
    assert username_from_text("vpn from user analyst-1 at 10.0.0.5") == "analyst-1"
    assert username_from_text("auth user: SOC_admin result=ok") == "SOC_admin"
    assert username_from_text("username=svc.account action=login") == "svc.account"
