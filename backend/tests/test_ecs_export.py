"""ECS export: field mapping, NDJSON endpoints, access control and audit."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.main import app
from app.models.audit_event import AuditEvent
from app.models.detection_rule_setting import DetectionRuleSetting
from app.models.role import Role
from app.models.user import User
from app.security import current_user
from app.services import ecs
from app.services.ecs import ECS_VERSION, alert_to_ecs, event_to_ecs


client = TestClient(app)
SAMPLES = Path(__file__).resolve().parents[2] / "sample-logs"


def stored_log(**overrides):
    values = {
        "id": 41,
        "upload_id": "0b0e7c06-6f0f-4d0e-9a53-0d6a4b0f3f11",
        "source_filename": "fw.log",
        "source_format": "cef",
        "line_number": 7,
        "event_timestamp": datetime(2026, 1, 10, 8, 0, 1, tzinfo=timezone.utc),
        "event_type": "login_attempt",
        "status": "FAILED",
        "severity": "MEDIUM",
        "raw_message": "CEF:0|Acme|GateKeeper|4.2|100|SSH login failed|6|src=203.0.113.50",
        "ingested_at": datetime(2026, 1, 10, 9, 0, 0, tzinfo=timezone.utc),
        "parsed_data": {
            "timestamp": "2026-01-10T08:00:01Z",
            "ip_address": "203.0.113.50",
            "username": "root",
            "event_type": "login_attempt",
            "status": "FAILED",
            "hostname": "fw01",
            "process": "sshd",
            "pid": 1234,
            "message": "Failed password for root",
            "dest_ip": "10.0.0.5",
            "destination_port": "22",
            "protocol": "TCP",
            "bytes_out": "98000",
            "bytes_in": "120",
            "domain": "intranet.example.test",
        },
    }
    values.update(overrides)
    return SimpleNamespace(**values)


# --- mapping (no database) -------------------------------------------------


@pytest.mark.no_db
def test_event_maps_onto_ecs_field_names():
    document = event_to_ecs(stored_log())

    assert document["@timestamp"] == "2026-01-10T08:00:01Z"
    assert document["ecs"] == {"version": ECS_VERSION}
    assert document["message"] == "Failed password for root"
    assert document["event"] == {
        "id": "41",
        "kind": "event",
        "category": ["authentication"],
        "type": ["start"],
        "action": "login_attempt",
        "outcome": "failure",
        "dataset": "cybershield.cef",
        "module": "cybershield",
        "ingested": "2026-01-10T09:00:00Z",
        "original": "CEF:0|Acme|GateKeeper|4.2|100|SSH login failed|6|src=203.0.113.50",
    }
    assert document["source"] == {"ip": "203.0.113.50", "bytes": 98000}
    assert document["destination"] == {
        "ip": "10.0.0.5", "port": 22, "domain": "intranet.example.test", "bytes": 120,
    }
    assert document["user"] == {"name": "root"}
    assert document["host"] == {"name": "fw01"}
    assert document["process"] == {"name": "sshd", "pid": 1234}
    assert document["network"] == {"transport": "tcp"}
    assert document["log"] == {"level": "medium", "file": {"path": "fw.log"}}
    assert document["related"] == {
        "ip": ["203.0.113.50", "10.0.0.5"],
        "user": ["root"],
        "hosts": ["fw01", "intranet.example.test"],
    }
    assert document["cybershield"]["line_number"] == 7


@pytest.mark.no_db
def test_event_with_little_data_emits_no_empty_fields():
    document = event_to_ecs(stored_log(
        event_timestamp=None,
        event_type="security_event",
        status="UNKNOWN",
        severity=None,
        parsed_data={"message": "something happened"},
    ))

    # ECS requires @timestamp; without an event time the ingest time stands in.
    assert document["@timestamp"] == "2026-01-10T09:00:00Z"
    assert document["event"]["outcome"] == "unknown"
    assert document["event"]["type"] == ["info"]
    assert "category" not in document["event"]
    for absent in ("source", "destination", "user", "host", "process", "network", "dns", "file", "related"):
        assert absent not in document
    assert document["log"] == {"file": {"path": "fw.log"}}


@pytest.mark.no_db
def test_alert_maps_rule_and_attack_technique():
    alert = SimpleNamespace(
        id=9,
        upload_id="0b0e7c06-6f0f-4d0e-9a53-0d6a4b0f3f11",
        rule="brute_force_login",
        title="Brute force login",
        severity="HIGH",
        status="OPEN",
        investigation_state="NEW",
        source_ip="203.0.113.50",
        username="root",
        hostname=None,
        event_count=6,
        time_window_seconds=60,
        first_seen=datetime(2026, 1, 10, 8, 0, 1, tzinfo=timezone.utc),
        last_seen=datetime(2026, 1, 10, 8, 0, 26, tzinfo=timezone.utc),
        description="6 failed logins from 203.0.113.50",
        matched_line_numbers=[2, 3, 4, 5, 6, 7],
        mitre_technique="T1110.001",
        confidence=80,
        entity_type="source_ip",
        created_at=datetime(2026, 1, 10, 9, 0, 0, tzinfo=timezone.utc),
    )
    document = alert_to_ecs(alert)

    assert document["@timestamp"] == "2026-01-10T08:00:26Z"
    assert document["event"]["kind"] == "alert"
    assert document["event"]["category"] == ["intrusion_detection"]
    assert document["event"]["severity"] == 3
    assert document["event"]["risk_score"] == 80
    assert document["event"]["start"] == "2026-01-10T08:00:01Z"
    assert document["rule"] == {
        "id": "brute_force_login",
        "name": "Brute force login",
        "description": "6 failed logins from 203.0.113.50",
    }
    assert document["threat"] == {
        "framework": "MITRE ATT&CK",
        "technique": {
            "id": ["T1110"],
            "reference": ["https://attack.mitre.org/techniques/T1110/"],
            "subtechnique": {"id": ["T1110.001"]},
        },
    }
    assert document["source"] == {"ip": "203.0.113.50"}
    assert "host" not in document
    assert document["cybershield"]["event_count"] == 6


@pytest.mark.no_db
def test_alert_without_a_technique_has_no_threat_block():
    alert = SimpleNamespace(
        id=1, upload_id="u", rule="custom", title="Custom", severity="LOW", status="OPEN",
        investigation_state="NEW", source_ip=None, username=None, hostname=None, event_count=1,
        time_window_seconds=0, first_seen=None, last_seen=None, description="d",
        matched_line_numbers=[], mitre_technique=None, confidence=50, entity_type="source_ip",
        created_at=datetime(2026, 1, 10, 9, 0, 0),
    )
    document = alert_to_ecs(alert)

    assert "threat" not in document
    # A naive database timestamp is treated as UTC.
    assert document["@timestamp"] == "2026-01-10T09:00:00Z"


# --- endpoints -------------------------------------------------------------


def make_user(db: Session, role_name: str) -> User:
    role = db.scalar(select(Role).where(Role.name == role_name))
    if role is None:
        role = Role(name=role_name, description=f"{role_name} test role")
        db.add(role)
        db.flush()
    name = f"ecs-{uuid4().hex[:8]}"
    user = User(role_id=role.id, username=name, email=f"{name}@example.test",
                password_hash="unused", is_active=True)
    db.add(user)
    db.commit()
    user.role = role
    return user


@pytest.fixture
def signed_in(db_session):
    def _sign_in(role_name: str = "Analyst") -> User:
        user = make_user(db_session, role_name)
        app.dependency_overrides[current_user] = lambda: user
        return user

    yield _sign_in
    app.dependency_overrides.pop(current_user, None)


@pytest.fixture
def cef_upload(db_session, signed_in):
    db_session.execute(delete(DetectionRuleSetting))
    db_session.commit()
    signed_in("Admin")
    response = client.post(
        "/upload",
        files={"logfile": ("cef_bruteforce.log", BytesIO((SAMPLES / "cef_bruteforce.log").read_bytes()), "text/plain")},
    )
    assert response.status_code == 200, response.text
    return response.json()["upload"]["upload_id"]


def ndjson(response) -> list[dict]:
    return [json.loads(line) for line in response.text.splitlines()]


def test_events_export_is_ndjson_of_ecs_documents(cef_upload, signed_in):
    signed_in("Analyst")
    response = client.get(f"/events/export?format=ecs&upload_id={cef_upload}")

    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("application/x-ndjson")
    assert response.headers["content-disposition"].startswith('attachment; filename="cybershield-events-ecs-')
    assert response.headers["x-ecs-version"] == ECS_VERSION
    assert response.headers["x-export-count"] == "8"
    assert response.headers["x-export-truncated"] == "false"

    documents = ndjson(response)
    assert len(documents) == 8
    first = documents[0]
    assert first["@timestamp"] == "2026-01-10T08:00:01Z"
    assert first["event"]["outcome"] == "failure"
    assert first["event"]["category"] == ["authentication"]
    assert first["event"]["dataset"] == "cybershield.cef"
    assert first["source"]["ip"] == "203.0.113.50"
    assert first["destination"] == {"ip": "10.0.0.5", "port": 22}
    assert first["user"]["name"] == "root"
    assert first["host"]["name"] == "fw01"
    assert first["event"]["original"].startswith("<134>Jan 10 08:00:01 fw01 CEF:0|")
    assert {doc["cybershield"]["upload_id"] for doc in documents} == {cef_upload}


def test_events_export_time_filter_narrows_the_result(cef_upload):
    response = client.get(
        "/events/export",
        params={"upload_id": cef_upload, "from": "2026-01-10T08:01:00Z", "to": "2026-01-10T08:01:30Z"},
    )

    assert [doc["user"]["name"] for doc in ndjson(response)] == ["alice"]


def test_alerts_export_carries_the_rule_and_technique(cef_upload):
    response = client.get(f"/alerts/export?format=ecs&upload_id={cef_upload}")

    assert response.status_code == 200, response.text
    brute_force = [doc for doc in ndjson(response) if doc["rule"]["id"] == "brute_force_login"]
    assert len(brute_force) == 1
    assert brute_force[0]["event"]["kind"] == "alert"
    assert brute_force[0]["source"]["ip"] == "203.0.113.50"
    assert brute_force[0]["threat"]["technique"]["id"] == ["T1110"]
    assert brute_force[0]["threat"]["technique"]["subtechnique"]["id"] == ["T1110.001"]


def test_export_stops_at_the_cap_and_says_so(cef_upload, monkeypatch):
    monkeypatch.setattr(ecs, "EXPORT_ROW_LIMIT", 3)
    monkeypatch.setattr("app.routers.export.EXPORT_ROW_LIMIT", 3)

    response = client.get(f"/events/export?upload_id={cef_upload}")

    assert len(ndjson(response)) == 3
    assert response.headers["x-export-count"] == "3"
    assert response.headers["x-export-truncated"] == "true"


def test_exports_are_recorded_in_the_audit_log(cef_upload, signed_in, db_session):
    analyst = signed_in("Analyst")
    client.get(f"/events/export?upload_id={cef_upload}")
    client.get("/alerts/export")

    events = db_session.scalars(
        select(AuditEvent).where(AuditEvent.actor_user_id == analyst.id).order_by(AuditEvent.id)
    ).all()
    assert [event.action for event in events] == ["export.events", "export.alerts"]
    assert events[0].target_id == cef_upload
    assert events[0].detail == {"format": "ecs", "count": 8, "truncated": False}


@pytest.mark.parametrize("path", ["/events/export", "/alerts/export"])
def test_viewers_cannot_export(path, signed_in):
    signed_in("Viewer")

    assert client.get(path).status_code == 403


@pytest.mark.parametrize("path", ["/events/export", "/alerts/export", "/api/events/export"])
def test_export_requires_sign_in(path):
    assert client.get(path).status_code == 401


@pytest.mark.parametrize("path", ["/events/export?format=ocsf", "/alerts/export?format=csv", "/events/export?upload_id=nope"])
def test_unsupported_format_or_bad_filter_is_rejected(path, signed_in):
    signed_in("Analyst")

    assert client.get(path).status_code == 422
