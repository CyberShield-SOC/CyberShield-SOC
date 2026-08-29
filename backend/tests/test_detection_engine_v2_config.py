from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.detection.engine import DetectionEngine
from app.detection.models import LogRecord, RuleConfig
from app.main import app
from app.models.role import Role
from app.models.user import User
from app.security import current_user


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
    assert all(item.name and item.config.window_seconds for item in metadata)


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
