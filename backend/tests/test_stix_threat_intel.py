"""STIX 2.1 threat-intel: bundle parsing, import through the API, export."""

from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.main import app
from app.models.audit_event import AuditEvent
from app.models.role import Role
from app.models.user import User
from app.repositories.threat_intel_repository import ThreatFeedError, parse_stix_feed
from app.security import current_user
from app.services.stix import StixError, looks_like_json, parse_stix_bundle


client = TestClient(app)
NOW = datetime(2026, 6, 1, tzinfo=timezone.utc)


def indicator(pattern: str, **extra) -> dict:
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{uuid4()}",
        "created": "2026-01-01T00:00:00.000Z",
        "modified": "2026-01-01T00:00:00.000Z",
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": "2026-01-01T00:00:00.000Z",
        **extra,
    }


def bundle(*objects: dict) -> str:
    return json.dumps({"type": "bundle", "id": f"bundle--{uuid4()}", "objects": list(objects)})


# --- parsing (no database) -------------------------------------------------


@pytest.mark.no_db
def test_bundle_yields_addresses_ranges_and_domains():
    content = bundle(
        {"type": "identity", "id": f"identity--{uuid4()}", "name": "Feed owner"},
        indicator("[ipv4-addr:value = '198.51.100.7']"),
        indicator("[ipv4-addr:value ISSUBSET '203.0.113.0/24']"),
        indicator("[ipv6-addr:value = '2001:db8::1']"),
        indicator("[domain-name:value = 'Evil.Example.TEST']"),
        indicator("[ipv4-addr:value = '192.0.2.1' OR ipv4-addr:value = '192.0.2.2']"),
    )

    indicators, rejected = parse_stix_feed(content)

    assert rejected == 0
    assert dict(indicators) == {
        "198.51.100.7": "ip",
        "203.0.113.0/24": "cidr",
        "2001:db8::1": "ip",
        "evil.example.test": "domain",
        "192.0.2.1": "ip",
        "192.0.2.2": "ip",
    }


@pytest.mark.no_db
def test_indicators_the_platform_cannot_match_are_counted_not_dropped_silently():
    content = bundle(
        indicator("[ipv4-addr:value = '198.51.100.7']"),
        indicator("[file:hashes.'SHA-256' = 'aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f']"),
        indicator("[url:value = 'http://evil.example.test/a']"),
        indicator("[ipv4-addr:value = '198.51.100.8']", revoked=True),
        indicator("[ipv4-addr:value = '198.51.100.9']", valid_until="2026-02-01T00:00:00Z"),
        indicator("alert tcp any any -> any any", pattern_type="snort"),
        indicator("[ipv4-addr:value = 'not-an-address']"),
        {"type": "malware", "id": f"malware--{uuid4()}", "name": "context only"},
    )

    values, rejected = parse_stix_bundle(content, now=NOW)
    assert values == ["198.51.100.7", "not-an-address"]
    assert rejected == 5

    # The repository layer then validates each value as the text feed does.
    indicators, rejected = parse_stix_feed(content)
    assert dict(indicators) == {"198.51.100.7": "ip"}
    assert rejected == 6


@pytest.mark.no_db
def test_an_indicator_still_inside_its_validity_window_is_kept():
    content = bundle(indicator("[ipv4-addr:value = '198.51.100.9']", valid_until="2027-01-01T00:00:00Z"))

    assert parse_stix_bundle(content, now=NOW) == (["198.51.100.9"], 0)


@pytest.mark.no_db
@pytest.mark.parametrize(
    "content",
    [
        "{not json",
        '{"type": "report", "objects": []}',
        '{"type": "bundle"}',
        '{"type": "bundle", "objects": {"a": 1}}',
    ],
    ids=["invalid-json", "not-a-bundle", "no-objects", "objects-not-a-list"],
)
def test_json_that_is_not_a_bundle_is_refused(content):
    with pytest.raises(StixError):
        parse_stix_bundle(content)
    with pytest.raises(ThreatFeedError):
        parse_stix_feed(content)


@pytest.mark.no_db
def test_only_content_opening_with_a_brace_is_treated_as_json():
    assert looks_like_json('﻿ \n{"type": "bundle"}')
    assert not looks_like_json("198.51.100.7\n# {not json}")


# --- API -------------------------------------------------------------------


@pytest.fixture
def signed_in(db_session):
    def _sign_in(role_name: str = "Analyst") -> User:
        role = db_session.scalar(select(Role).where(Role.name == role_name))
        if role is None:
            role = Role(name=role_name, description=f"{role_name} test role")
            db_session.add(role)
            db_session.flush()
        name = f"stix-{uuid4().hex[:8]}"
        user = User(role_id=role.id, username=name, email=f"{name}@example.test",
                    password_hash="unused", is_active=True)
        db_session.add(user)
        db_session.commit()
        user.role = role
        app.dependency_overrides[current_user] = lambda: user
        return user

    yield _sign_in
    app.dependency_overrides.pop(current_user, None)


def test_posting_a_bundle_imports_it_and_reports_the_format(signed_in):
    signed_in("Analyst")
    source = f"stix-{uuid4().hex[:8]}"
    content = bundle(
        indicator("[ipv4-addr:value = '198.51.100.7']"),
        indicator("[domain-name:value = 'evil.example.test']"),
        indicator("[file:name = 'dropper.exe']"),
    )

    response = client.post("/threat-intel/feeds", json={"source": source, "content": content})

    assert response.status_code == 200, response.text
    body = response.json()
    assert (body["format"], body["imported"], body["rejected_lines"]) == ("stix", 2, 1)
    stored = client.get("/threat-intel/indicators", params={"source": source}).json()["indicators"]
    assert {(row["indicator"], row["type"]) for row in stored} == {
        ("198.51.100.7", "ip"), ("evil.example.test", "domain"),
    }


def test_text_feeds_still_import_as_text(signed_in):
    signed_in("Analyst")
    source = f"text-{uuid4().hex[:8]}"

    body = client.post("/threat-intel/feeds", json={"source": source, "content": "198.51.100.7\n"}).json()

    assert (body["format"], body["imported"]) == ("text", 1)


def test_a_bundle_with_nothing_matchable_is_a_422_with_a_clear_reason(signed_in):
    signed_in("Analyst")
    content = bundle(indicator("[file:name = 'dropper.exe']"))

    response = client.post("/threat-intel/feeds", json={"source": "hashes-only", "content": content})

    assert response.status_code == 422
    assert "STIX bundle contained no IP, CIDR, or domain" in response.json()["detail"]


def test_export_is_a_valid_bundle_with_stable_ids_that_round_trips(signed_in, db_session):
    analyst = signed_in("Analyst")
    source = f"round-{uuid4().hex[:8]}"
    client.post("/threat-intel/feeds", json={
        "source": source,
        "content": "198.51.100.7\n203.0.113.0/24\n2001:db8::/48\nevil.example.test\n",
        "description": "Round-trip feed",
    })

    response = client.get(f"/threat-intel/feeds/{source}/stix")

    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("application/stix+json")
    assert response.headers["content-disposition"] == f'attachment; filename="{source}.stix.json"'
    exported = response.json()
    assert exported["type"] == "bundle"
    assert re.fullmatch(r"bundle--[0-9a-f-]{36}", exported["id"])

    identity, *indicators = exported["objects"]
    assert identity["type"] == "identity" and identity["spec_version"] == "2.1"
    assert sorted(item["pattern"] for item in indicators) == [
        "[domain-name:value = 'evil.example.test']",
        "[ipv4-addr:value = '198.51.100.7']",
        "[ipv4-addr:value = '203.0.113.0/24']",
        "[ipv6-addr:value = '2001:db8::/48']",
    ]
    timestamp = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z")
    for item in indicators:
        # Every property STIX 2.1 requires of an indicator.
        assert item["spec_version"] == "2.1"
        assert re.fullmatch(r"indicator--[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", item["id"])
        assert item["pattern_type"] == "stix"
        assert all(timestamp.fullmatch(item[key]) for key in ("created", "modified", "valid_from"))
        assert item["created_by_ref"] == identity["id"]
        assert item["description"] == "Round-trip feed"

    again = client.get(f"/threat-intel/feeds/{source}/stix").json()
    assert [item["id"] for item in again["objects"]] == [item["id"] for item in exported["objects"]]

    # What we export, we can import: same indicators under a new name.
    copy = f"{source}-copy"
    imported = client.post("/threat-intel/feeds", json={"source": copy, "content": json.dumps(exported)}).json()
    assert (imported["format"], imported["imported"], imported["rejected_lines"]) == ("stix", 4, 0)
    original = client.get("/threat-intel/indicators", params={"source": source}).json()["indicators"]
    copied = client.get("/threat-intel/indicators", params={"source": copy}).json()["indicators"]
    assert [(r["indicator"], r["type"]) for r in copied] == [(r["indicator"], r["type"]) for r in original]

    audited = db_session.scalars(
        select(AuditEvent).where(AuditEvent.actor_user_id == analyst.id, AuditEvent.action == "export.threat_feed")
    ).all()
    assert len(audited) == 2
    assert audited[0].target_label == source
    assert audited[0].detail == {"format": "stix-2.1", "count": 4}


def test_exporting_an_unknown_feed_is_404(signed_in):
    signed_in("Analyst")

    assert client.get("/threat-intel/feeds/no-such-feed/stix").status_code == 404


def test_viewers_cannot_export_and_export_requires_sign_in(signed_in):
    assert client.get("/threat-intel/feeds/any/stix").status_code == 401
    signed_in("Viewer")
    assert client.get("/threat-intel/feeds/any/stix").status_code == 403
