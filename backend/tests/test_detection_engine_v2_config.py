from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.detection.engine import DetectionEngine
from app.detection.models import LogRecord, RuleConfig
from app.main import app
from app.models.role import Role
from app.models.user import User
from app.repositories.detection_rule_setting_repository import effective_rule_configs
from app.security import current_user, hash_password

client = TestClient(app)


_BASE = datetime(2026, 6, 14, 2, 11, 0, tzinfo=timezone.utc)

pytestmark = pytest.mark.no_db


def _ts(delta_s: int) -> str:
    return (_BASE + timedelta(seconds=delta_s)).strftime("%Y-%m-%dT%H:%M:%SZ")


def test_engine_v2_applies_rule_threshold_overrides():
    engine = DetectionEngine.from_config(
        {
            "brute_force_login": RuleConfig(threshold=3, window_seconds=60),
        }
    )
    records = [
        LogRecord(
            line_number=index + 1,
            timestamp=_ts(index),
            ip_address="203.0.113.40",
            username="root",
            event_type="login_attempt",
            status="FAILED",
        )
        for index in range(3)
    ]

    alerts = engine.run(records)

    assert len(alerts) == 1
    assert alerts[0].rule == "brute_force_login"
    assert alerts[0].count == 3


def test_engine_v2_can_disable_a_rule_and_exposes_metadata():
    engine = DetectionEngine.from_config(
        {
            "brute_force_login": {"enabled": False},
        }
    )

    assert "brute_force_login" not in {rule.name for rule in engine.rules}
    metadata = engine.rule_metadata()
    assert metadata
    assert all(item.name for item in metadata)
    # Only the frequency/window-based rules carry a window_seconds — several
    # newer rules (e.g. direct_root_login) key off a cooldown instead.
    by_name = {item.name: item for item in metadata}
    assert by_name["invalid_user_enumeration"].config.window_seconds


def test_detection_rules_endpoint_exposes_active_rule_metadata():
    from fastapi.testclient import TestClient

    user = User(
        id=1,
        role_id=1,
        username="viewer",
        email="viewer@example.test",
        password_hash="not-used",
        is_active=True,
    )
    user.role = Role(id=1, name="Viewer")
    app.dependency_overrides[current_user] = lambda: user
    try:
        response = TestClient(app).get("/detection/rules")
    finally:
        app.dependency_overrides.pop(current_user, None)

    assert response.status_code == 200
    payload = response.json()
    assert payload["success"] is True
    assert "brute_force_login" in {rule["name"] for rule in payload["rules"]}


# ── Sprint 5: persisted rule overrides ────────────────────────────────────────

def _ensure_role(db: Session, name: str) -> Role:
    role = db.scalar(select(Role).where(Role.name == name))
    if role is None:
        role = Role(name=name, description=f"{name} test role")
        db.add(role)
        db.flush()
    return role


def _persist_user(db: Session, role_name: str) -> User:
    role = _ensure_role(db, role_name)
    suffix = uuid4().hex[:8]
    user = User(
        username=f"rule-config-{suffix}",
        email=f"rule-config-{suffix}@example.test",
        full_name="Rule Config Tester",
        password_hash=hash_password("RuleConfigPassphrase-42!"),
        role_id=role.id,
    )
    db.add(user)
    db.flush()
    db.refresh(user)
    user.role = role
    return user


@pytest.mark.db
def test_effective_rule_configs_merges_env_then_db_override(db_session: Session):
    user = _persist_user(db_session, "Admin")
    from app.repositories.detection_rule_setting_repository import upsert_rule_setting

    upsert_rule_setting(
        db_session,
        rule_name="brute_force_login",
        updates={"threshold": 9},
        updated_by=user.id,
    )
    db_session.commit()

    configs = effective_rule_configs(
        db_session,
        {"brute_force_login": {"window_seconds": 45}},
    )

    assert configs["brute_force_login"].threshold == 9
    assert configs["brute_force_login"].window_seconds == 45
    assert configs["brute_force_login"].enabled is True


@pytest.mark.db
def test_patch_detection_rule_persists_and_get_reflects_it(db_session: Session):
    user = _persist_user(db_session, "Admin")
    app.dependency_overrides[current_user] = lambda: user
    try:
        patch_response = client.patch(
            "/detection/rules/port_scan",
            json={"enabled": False, "threshold": 25},
        )
        assert patch_response.status_code == 200
        assert patch_response.json()["rule"]["config"]["enabled"] is False
        assert patch_response.json()["rule"]["config"]["threshold"] == 25

        get_response = client.get("/detection/rules")
        assert get_response.status_code == 200
        rule = next(r for r in get_response.json()["rules"] if r["name"] == "port_scan")
        assert rule["config"]["enabled"] is False
        assert rule["config"]["threshold"] == 25
    finally:
        app.dependency_overrides.pop(current_user, None)


@pytest.mark.db
def test_patch_detection_rule_rejects_unknown_rule_name(db_session: Session):
    user = _persist_user(db_session, "Admin")
    app.dependency_overrides[current_user] = lambda: user
    try:
        response = client.patch("/detection/rules/not_a_real_rule", json={"enabled": False})
        assert response.status_code == 404
    finally:
        app.dependency_overrides.pop(current_user, None)


@pytest.mark.db
def test_patch_detection_rule_requires_write_role(db_session: Session):
    user = _persist_user(db_session, "Viewer")
    app.dependency_overrides[current_user] = lambda: user
    try:
        response = client.patch("/detection/rules/port_scan", json={"enabled": False})
        assert response.status_code == 403
    finally:
        app.dependency_overrides.pop(current_user, None)


def test_engine_v2_applies_confidence_and_reused_threshold_overrides():
    engine = DetectionEngine.from_config({
        "brute_force_login": {"confidence": 95},
        "dormant_account_activity": {"threshold": 90},
    })
    by_name = {rule.name: rule for rule in engine.rules}

    assert by_name["brute_force_login"].confidence == 95
    assert by_name["dormant_account_activity"].threshold == 90

    records = [
        LogRecord(line_number=i + 1, timestamp=f"2026-06-14T14:00:0{i}Z", ip_address="203.0.113.4",
                  username="root", event_type="login_attempt", status="FAILED")
        for i in range(5)
    ]
    alerts = [a for a in engine.run(records) if a.rule == "brute_force_login"]
    assert alerts and alerts[0].confidence == 95


def test_original_rules_accept_a_configured_cooldown():
    from app.repositories.detection_rule_setting_repository import effective_rule_configs

    class _NoRows:
        def scalars(self, _):
            class _R:
                def all(self):
                    return []
            return _R()

    configs = effective_rule_configs(_NoRows(), {"brute_force_login": {"cooldown_seconds": 600}})
    assert configs["brute_force_login"].cooldown_seconds == 600
    assert configs["port_scan"].cooldown_seconds is None
