"""End-to-end: a syslog upload through /upload reaches the new host-event
rules, persists the v2 alert fields, and respects cooldown suppression."""

from __future__ import annotations

import sys
from io import BytesIO
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.main import app
from app.models.role import Role
from app.models.user import User
from app.security import current_user

client = TestClient(app)


@pytest.fixture(autouse=True)
def authenticated_admin(db_session):
    admin_role = db_session.scalar(select(Role).where(Role.name == "Admin"))
    if admin_role is None:
        admin_role = Role(name="Admin", description="Administrator")
        db_session.add(admin_role)
        db_session.flush()

    suffix = uuid4().hex
    admin_user = User(
        role_id=admin_role.id,
        username=f"v2_admin_{suffix}",
        email=f"v2_admin_{suffix}@example.test",
        password_hash="not-used",
        is_active=True,
    )
    db_session.add(admin_user)
    db_session.commit()

    app.dependency_overrides[current_user] = lambda: admin_user
    yield
    app.dependency_overrides.pop(current_user, None)


def upload(lines: list[str], name="auth.log"):
    content = ("\n".join(lines) + "\n").encode()
    return client.post("/upload", files={"logfile": (name, BytesIO(content), "text/plain")})


def test_syslog_upload_fires_host_event_rules_with_v2_fields():
    host = f"h{uuid4().hex[:8]}"
    response = upload([
        f"Jun 14 14:00:00 {host} useradd[4021]: new user: name=mallory, UID=1010, GID=1010, home=/home/mallory, shell=/bin/bash",
        f"Jun 14 14:00:05 {host} usermod[4022]: add 'mallory' to group 'sudo'",
        f"Jun 14 14:00:10 {host} systemd[1]: Stopped Security Auditing Service (auditd).",
    ])

    assert response.status_code == 200
    by_rule = {alert["rule"]: alert for alert in response.json()["alerts"]}

    created = by_rule["new_account_created"]
    assert created["mitre_technique"] == "T1136"
    assert created["entity_type"] == "host"
    assert created["entity_id"] == host
    assert created["hostname"] == host
    assert created["title"] == "New account created"

    assert by_rule["privileged_group_modified"]["username"] == "mallory"
    assert by_rule["log_tampering"]["severity"] == "CRITICAL"


def test_cooldown_suppresses_repeat_alert_across_uploads():
    host = f"h{uuid4().hex[:8]}"
    first = upload([f"Jun 14 14:00:00 {host} useradd[1]: new user: name=a1, UID=2001"])
    second = upload([f"Jun 14 14:10:00 {host} useradd[2]: new user: name=a2, UID=2002"])

    assert [a["rule"] for a in first.json()["alerts"]] == ["new_account_created"]
    # Default cooldown for new_account_created is 30 min, same host => suppressed.
    assert second.json()["alerts"] == []


def test_detection_rules_endpoint_exposes_technique_and_entity_type():
    response = client.get("/detection/rules")
    assert response.status_code == 200
    rules = {rule["name"]: rule for rule in response.json()["rules"]}

    assert len(rules) == 30
    assert rules["brute_force_login"]["mitre_technique"] == "T1110.001"
    assert rules["lateral_movement_chain"]["entity_type"] == "account"
    assert rules["new_account_created"]["config"]["cooldown_seconds"] == 1800


def test_allowlist_is_configurable_via_api_and_takes_effect():
    patch = client.patch(
        "/detection/rules/service_account_interactive",
        json={"allowlist": ["svc-deploy"]},
    )
    assert patch.status_code == 200
    assert patch.json()["rule"]["config"]["allowlist"] == ["svc-deploy"]

    response = upload(["Jun 14 14:00:00 web01 sshd[9]: Accepted password for svc-deploy from 10.1.1.1 port 5000 ssh2"])
    assert any(a["rule"] == "service_account_interactive" for a in response.json()["alerts"])
