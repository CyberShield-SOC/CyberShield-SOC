"""Threat-intel feed API and rule params/tunable validation."""

from __future__ import annotations

import sys
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


def as_role(db_session, role_name: str) -> User:
    role = db_session.scalar(select(Role).where(Role.name == role_name))
    if role is None:
        role = Role(name=role_name, description=role_name)
        db_session.add(role)
        db_session.flush()
    user = User(
        role_id=role.id, username=f"v3-{uuid4().hex[:8]}", email=f"v3-{uuid4().hex[:8]}@example.test",
        password_hash="x", is_active=True,
    )
    user.role = role
    db_session.add(user)
    db_session.commit()
    app.dependency_overrides[current_user] = lambda: user
    return user


@pytest.fixture(autouse=True)
def reset_overrides():
    yield
    app.dependency_overrides.pop(current_user, None)


def test_feed_import_list_indicators_and_delete(db_session):
    as_role(db_session, "Admin")
    source = f"feed {uuid4().hex[:6]}"

    created = client.post("/threat-intel/feeds", json={"source": source, "content": "1.2.3.4\nevil.com\n10.0.0.0/8\njunk!!\n"})
    assert created.status_code == 200
    assert created.json()["imported"] == 3 and created.json()["rejected_lines"] == 1

    feeds = {f["source"]: f for f in client.get("/threat-intel/feeds").json()["feeds"]}
    assert feeds[source]["by_type"] == {"ip": 1, "cidr": 1, "domain": 1}

    replaced = client.post("/threat-intel/feeds", json={"source": source, "content": "5.6.7.8\n", "replace": True})
    assert replaced.json()["replaced"] == 3
    indicators = client.get("/threat-intel/indicators", params={"source": source}).json()["indicators"]
    assert [i["indicator"] for i in indicators] == ["5.6.7.8"]

    assert client.delete(f"/threat-intel/feeds/{source}").json()["removed"] == 1
    assert client.delete(f"/threat-intel/feeds/{source}").status_code == 404


def test_feed_without_indicators_is_rejected(db_session):
    as_role(db_session, "Analyst")
    response = client.post("/threat-intel/feeds", json={"source": "empty", "content": "# nothing\n"})
    assert response.status_code == 422


def test_viewer_cannot_import_feeds(db_session):
    as_role(db_session, "Viewer")
    response = client.post("/threat-intel/feeds", json={"source": "x", "content": "1.2.3.4"})
    assert response.status_code == 403


def test_rule_payload_exposes_tunables_and_default_params(db_session):
    as_role(db_session, "Viewer")
    rules = {r["name"]: r for r in client.get("/detection/rules").json()["rules"]}
    assert "params" in rules["dns_tunneling"]["tunables"]
    assert rules["dns_tunneling"]["default_params"] == {"min_subdomain_length": 30, "min_entropy": 3.5}
    assert "allowlist" not in rules["brute_force_login"]["tunables"]


def test_params_patch_merges_key_by_key(db_session):
    as_role(db_session, "Admin")
    first = client.patch("/detection/rules/dns_tunneling", json={"params": {"min_entropy": 4.2}})
    assert first.status_code == 200, first.text
    second = client.patch("/detection/rules/dns_tunneling", json={"params": {"min_subdomain_length": 40}})
    assert second.json()["rule"]["config"]["params"] == {"min_subdomain_length": 40, "min_entropy": 4.2}


def test_unknown_param_and_unsupported_setting_are_rejected(db_session):
    as_role(db_session, "Admin")
    unknown = client.patch("/detection/rules/dns_tunneling", json={"params": {"entropy": 4}})
    assert unknown.status_code == 422
    unsupported = client.patch("/detection/rules/brute_force_login", json={"allowlist": ["1.2.3.4"]})
    assert unsupported.status_code == 422
    assert "allowlist" in unsupported.json()["detail"]
