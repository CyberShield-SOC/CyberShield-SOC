"""Sigma import and the custom-rule engine features it relies on."""

from __future__ import annotations

import sys
from io import BytesIO
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import delete, select

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.detection.models import LogRecord
from app.detection.normalize import log_record_from_entry
from app.detection.rules.custom_condition import CustomConditionRule, evaluate_condition
from app.main import app
from app.models.audit_event import AuditEvent
from app.models.custom_rule import CustomRule
from app.models.detection_rule_setting import DetectionRuleSetting
from app.models.role import Role
from app.models.user import User
from app.parsers.log_parser import parse_log
from app.schemas.custom_rule import ConditionPayload, CustomRuleCreate
from app.security import current_user
from app.services.sigma_import import SigmaUnsupported, parse_sigma, translate_rule


client = TestClient(app)
SIGMA = Path(__file__).resolve().parents[2] / "sample-logs" / "sigma"
RULES_FILE = SIGMA / "ssh_bruteforce_and_sudo.yml"
EVENTS_FILE = SIGMA / "ssh_bruteforce_events.log"


def rec(line: int, **fields) -> LogRecord:
    return LogRecord(line_number=line, timestamp=fields.pop("ts", "2026-03-03T09:00:00Z"), **fields)


def sigma(detection: dict, **extra) -> dict:
    return {"title": "Test rule", "detection": detection, **extra}


def sample_records() -> list[LogRecord]:
    parsed = parse_log(EVENTS_FILE.read_text(encoding="utf-8"), EVENTS_FILE.name)
    return [log_record_from_entry(entry, parsed["format"]) for entry in parsed["entries"]]


def run(translated) -> list:
    return CustomConditionRule(
        rule_id="R-T",
        display_name=translated.name,
        severity=translated.severity,
        conditions=translated.conditions,
        group_by=None if translated.group_by == "none" else translated.group_by,
        window_seconds=translated.window_seconds,
        min_count=translated.min_count,
        mitre_technique=translated.mitre_technique,
    ).analyze(sample_records())


# --- engine: new fields, operators, lists, NOT, minimum count --------------


@pytest.mark.no_db
@pytest.mark.parametrize(
    ("condition", "expected"),
    [
        ({"field": "process", "operator": "equals", "value": "SSHD"}, True),
        ({"field": "command", "operator": "startswith", "value": "/usr/bin"}, True),
        ({"field": "command", "operator": "endswith", "value": "nginx"}, True),
        ({"field": "command", "operator": "endswith", "value": "/bin/bash"}, False),
        ({"field": "hostname", "operator": "contains", "values": ["db", "bastion"]}, True),
        ({"field": "hostname", "operator": "contains", "values": ["db", "web"]}, False),
        ({"field": "hostname", "operator": "contains", "values": ["db", "web"], "negate": True}, True),
        ({"field": "dest_ip", "operator": "equals", "value": "10.0.0.5", "negate": True}, True),
        ({"field": "port", "operator": "equals", "values": ["22", "2222"]}, True),
    ],
)
def test_condition_features(condition, expected):
    record = rec(1, process="sshd", command="/usr/bin/systemctl restart nginx", hostname="bastion01", port=22)

    assert evaluate_condition(record, condition) is expected


@pytest.mark.no_db
def test_min_count_holds_back_buckets_that_are_too_small():
    records = [rec(i, ip_address="203.0.113.9", ts=f"2026-03-03T09:00:{i:02d}Z", status="FAILED") for i in range(1, 4)]
    records += [rec(10 + i, ip_address="192.0.2.1", ts=f"2026-03-03T09:00:{i:02d}Z", status="FAILED") for i in range(1, 6)]
    rule = CustomConditionRule(
        rule_id="R-200", display_name="Bursts", severity="high",
        conditions=[{"field": "status", "operator": "equals", "value": "FAILED"}],
        group_by="ip_address", window_seconds=60, min_count=5, mitre_technique="T1110",
    )

    alerts = rule.analyze(records)

    assert [(alert.source_ip, alert.count, alert.mitre_technique) for alert in alerts] == [("192.0.2.1", 5, "T1110")]


@pytest.mark.no_db
def test_condition_payload_rules_for_lists_and_negation():
    stored = ConditionPayload(field="process", operator="endswith", values=["a", "b"], negate=True).to_storage()
    assert stored == {"field": "process", "operator": "endswith", "values": ["a", "b"], "negate": True, "timezone": None}
    # A rule saved before lists existed keeps exactly its old stored shape.
    assert ConditionPayload(field="status", operator="equals", value="FAILED").to_storage() == {
        "field": "status", "operator": "equals", "value": "FAILED", "timezone": None,
    }
    for bad in (
        {"field": "process", "operator": "equals"},
        {"field": "process", "operator": "equals", "value": "a", "values": ["b"]},
        {"field": "process", "operator": "in", "values": ["a"]},
        {"field": "process", "operator": "equals", "values": ["a", "  "]},
        {"field": "port", "operator": "equals", "values": ["22", "http"]},
        {"field": "timestamp", "operator": "after", "values": ["2026-01-01T00:00:00Z"]},
    ):
        with pytest.raises(ValidationError):
            ConditionPayload(**bad)


@pytest.mark.no_db
def test_rule_level_fields_are_validated():
    base = {"name": "r", "conditions": [{"field": "status", "operator": "equals", "value": "FAILED"}]}

    rule = CustomRuleCreate.model_validate({**base, "window_seconds": 120, "min_count": 5, "mitre_technique": "t1110.001"})
    assert (rule.window_seconds, rule.min_count, rule.mitre_technique) == (120, 5, "T1110.001")
    for bad in ({"window_seconds": 59}, {"window_seconds": 86401}, {"min_count": 0}, {"mitre_technique": "TA0006"}):
        with pytest.raises(ValidationError):
            CustomRuleCreate.model_validate({**base, **bad})


# --- translation (no database) -------------------------------------------------


@pytest.mark.no_db
def test_fixture_rules_translate_and_fire_only_on_the_triggering_events():
    documents = parse_sigma(RULES_FILE.read_text(encoding="utf-8"))
    assert [label for label, *_ in documents] == [
        "Repeated SSH Password Failures From One Source",
        "Sudo To Root Running A Shell",
        "Encoded PowerShell Or Certutil Download",
        "Suspicious Regex Command",
    ]

    brute = translate_rule(documents[0][1], documents[0][3])
    assert (brute.severity, brute.tactic, brute.mitre_technique) == ("HIGH", "TA0006", "T1110.001")
    assert (brute.group_by, brute.window_seconds, brute.min_count) == ("ip_address", 60, 5)
    assert brute.external_id == "7c1f4d2e-5b3a-4e61-9a2c-1d8e6f0b3a71"
    assert brute.source_text.startswith("title: Repeated SSH Password Failures")
    # Fires for the 5-failure source; not the 4-failure near miss (192.0.2.44)
    # and not the filtered scanner (198.51.100.250), despite its 6 failures.
    assert [(alert.source_ip, alert.count) for alert in run(brute)] == [("203.0.113.77", 5)]

    sudo = translate_rule(documents[1][1])
    assert sudo.conditions[1] == {
        "field": "command", "operator": "endswith", "timezone": None, "values": ["/bin/bash", "/bin/sh"],
    }
    # /bin/bash fires; the systemctl near miss does not.
    assert [alert.matched_line_numbers for alert in run(sudo)] == [[17]]

    for document, reason in ((documents[2][1], "OR between selections"), (documents[3][1], "'re' modifier")):
        with pytest.raises(SigmaUnsupported, match=reason):
            translate_rule(document)


@pytest.mark.no_db
@pytest.mark.parametrize(
    ("value", "operator", "expected"),
    [
        ("*mimikatz*", "contains", "mimikatz"),
        ("*\\cmd.exe", "endswith", "\\cmd.exe"),
        ("/tmp/*", "startswith", "/tmp/"),
        ("C:\\\\x\\*y", "equals", "C:\\\\x*y"),
        ("exact", "equals", "exact"),
    ],
)
def test_plain_value_wildcards_become_operators(value, operator, expected):
    translated = translate_rule(sigma({"sel": {"CommandLine": value}, "condition": "sel"}))

    assert (translated.conditions[0]["operator"], translated.conditions[0]["value"]) == (operator, expected)


@pytest.mark.no_db
def test_modifiers_lists_keywords_and_numbers():
    translated = translate_rule(sigma({
        "sel": {
            "CommandLine|contains|all": ["-nop", "-w hidden"],
            "DestinationPort|gte": 1024,
            "User": ["svc_backup", "svc_sql"],
        },
        "keywords": ["Invoke-Mimikatz", "sekurlsa"],
        "condition": "sel and keywords",
    }))

    assert translated.conditions == [
        {"field": "command", "operator": "contains", "timezone": None, "value": "-nop"},
        {"field": "command", "operator": "contains", "timezone": None, "value": "-w hidden"},
        {"field": "port", "operator": ">", "timezone": None, "value": "1023"},
        {"field": "username", "operator": "equals", "timezone": None, "values": ["svc_backup", "svc_sql"]},
        {"field": "message", "operator": "contains", "timezone": None, "values": ["Invoke-Mimikatz", "sekurlsa"]},
    ]


@pytest.mark.no_db
def test_level_tags_and_aggregation_mapping():
    translated = translate_rule(sigma(
        {"sel": {"status": "FAILED"}, "timeframe": "15m", "condition": "sel | count() by User >= 10"},
        level="critical",
        tags=["attack.lateral-movement", "attack.t1021", "attack.t1021.004"],
        id="  abc  ",
    ))

    assert (translated.severity, translated.tactic, translated.mitre_technique) == ("CRITICAL", "TA0008", "T1021")
    assert (translated.group_by, translated.window_seconds, translated.min_count) == ("username", 900, 10)
    assert translated.external_id == "abc"
    assert translated.notes == []


@pytest.mark.no_db
def test_a_count_without_a_timeframe_says_which_window_it_used():
    translated = translate_rule(sigma({"sel": {"status": "FAILED"}, "condition": "sel | count() > 2"}))

    assert (translated.window_seconds, translated.min_count) == (600, 3)
    assert translated.notes == ["No timeframe was given for the count, so a 10-minute window is used."]


@pytest.mark.no_db
@pytest.mark.parametrize(
    ("detection", "reason"),
    [
        ({"sel": {"Hashes|contains": "abc"}, "condition": "sel"}, "field 'Hashes' has no CyberShield equivalent"),
        ({"sel": {"CommandLine|base64offset|contains": "x"}, "condition": "sel"}, "'base64offset' modifier"),
        ({"a": {"User": "x"}, "b": {"User": "y"}, "condition": "1 of a*"}, None),
        ({"sel1": {"User": "x"}, "sel2": {"User": "y"}, "condition": "1 of sel*"}, "an OR across selections"),
        ({"sel": [{"User": "x"}, {"User": "y"}], "condition": "sel"}, "list of alternatives"),
        ({"sel": {"User": "x"}, "f": {"Image": "a", "CommandLine": "b"}, "condition": "sel and not f"}, "negates several fields"),
        ({"sel": {"User": "x"}, "condition": "(sel)"}, "parentheses"),
        ({"f": {"User": "x"}, "condition": "not f"}, "only of negations"),
        ({"sel": {"CommandLine": "a*b"}, "condition": "sel"}, "wildcard inside a value"),
        ({"sel": {"CommandLine": ["cmd.exe", "*\\powershell.exe"]}, "condition": "sel"}, "mixing exact and wildcard"),
        ({"sel": {"User": None}, "condition": "sel"}, "only text and number values"),
        ({"sel": {"User": "x"}, "timeframe": "30s", "condition": "sel | count() > 3"}, "outside the supported"),
        ({"sel": {"User": "x"}, "condition": "sel | count(User) by SourceIp > 3"}, "aggregation"),
        ({"sel": {"User": "x"}, "condition": "sel | count() by Image > 3"}, "count\\(\\) by Image"),
        ({"sel": {"User": "x"}, "condition": "missing"}, "not defined"),
    ],
)
def test_unsupported_constructs_are_rejected_with_a_reason(detection, reason):
    if reason is None:
        # "1 of a*" over a single selection is just that selection.
        assert translate_rule(sigma(detection)).conditions[0]["value"] == "x"
        return
    with pytest.raises(SigmaUnsupported, match=reason):
        translate_rule(sigma(detection))


@pytest.mark.no_db
def test_correlation_rules_and_malformed_documents_are_rejected():
    with pytest.raises(SigmaUnsupported, match="correlation rules"):
        translate_rule({"title": "c", "correlation": {"type": "event_count"}})
    with pytest.raises(SigmaUnsupported, match="no title"):
        translate_rule({"detection": {"sel": {"User": "x"}, "condition": "sel"}})
    with pytest.raises(SigmaUnsupported, match="no detection"):
        translate_rule({"title": "t"})
    with pytest.raises(SigmaUnsupported, match="not a Sigma rule"):
        translate_rule(["a list"])


@pytest.mark.no_db
def test_yaml_is_read_safely_and_errors_are_per_document():
    content = "title: ok\ndetection: {sel: {User: x}, condition: sel}\n---\ntitle: [unclosed\n---\n!!python/object/apply:os.system ['echo pwned']\n"

    documents = parse_sigma(content)

    assert documents[0][2] is None
    assert documents[1][2].startswith("The YAML could not be read")
    # safe_load refuses Python object tags rather than executing them.
    assert documents[2][1] is None and documents[2][2].startswith("The YAML could not be read")


@pytest.mark.no_db
def test_an_import_is_capped():
    content = "\n---\n".join(f"title: r{i}\ndetection: {{sel: {{User: x}}, condition: sel}}" for i in range(51))

    with pytest.raises(SigmaUnsupported, match="at most 50"):
        parse_sigma(content)


# --- API -------------------------------------------------------------------


@pytest.fixture
def analyst(db_session):
    role = db_session.scalar(select(Role).where(Role.name == "Analyst"))
    if role is None:
        role = Role(name="Analyst", description="Analyst test role")
        db_session.add(role)
        db_session.flush()
    name = f"sigma-{uuid4().hex[:8]}"
    user = User(role_id=role.id, username=name, email=f"{name}@example.test", password_hash="unused", is_active=True)
    db_session.add(user)
    # Fixture rule ids are fixed, so clear any copy a manual run left behind.
    db_session.execute(delete(CustomRule).where(CustomRule.source == "sigma"))
    db_session.execute(delete(DetectionRuleSetting))
    db_session.commit()
    user.role = role
    app.dependency_overrides[current_user] = lambda: user
    yield user
    app.dependency_overrides.pop(current_user, None)


def test_import_creates_drafts_and_reports_every_rule(analyst, db_session):
    response = client.post("/custom-rules/import/sigma", json={"content": RULES_FILE.read_text(encoding="utf-8")})

    assert response.status_code == 200, response.text
    body = response.json()
    assert (body["created"], body["skipped"], body["rejected"]) == (2, 0, 2)
    created = [item for item in body["results"] if item["status"] == "created"]
    rule = created[0]["rule"]
    assert rule["status"] == "DRAFT"
    assert (rule["source"], rule["external_id"]) == ("sigma", "7c1f4d2e-5b3a-4e61-9a2c-1d8e6f0b3a71")
    assert (rule["min_count"], rule["window_seconds"], rule["group_by"]) == (5, 60, "ip_address")
    assert (rule["mitre_technique"], rule["tactic"], rule["severity"]) == ("T1110.001", "TA0006", "HIGH")
    assert rule["dsl"].startswith("title: Repeated SSH Password Failures")
    assert created[0]["notes"] == ["The logsource is not used: the rule runs on every uploaded event."]
    reasons = {item["title"]: item["reason"] for item in body["results"] if item["status"] == "rejected"}
    assert reasons == {
        "Encoded PowerShell Or Certutil Download": "Not imported: OR between selections is not supported.",
        "Suspicious Regex Command": "Not imported: CommandLine|re: the 're' modifier is not supported.",
    }

    audit = db_session.scalars(
        select(AuditEvent).where(AuditEvent.actor_user_id == analyst.id, AuditEvent.action == "rule.custom.import")
    ).one()
    assert audit.detail["created"] == 2 and audit.detail["rejected"] == 2
    assert audit.detail["rule_ids"] == [item["rule_id"] for item in created]


def test_reimporting_the_same_rules_skips_them(analyst):
    content = RULES_FILE.read_text(encoding="utf-8")
    first = client.post("/custom-rules/import/sigma", json={"content": content}).json()

    second = client.post("/custom-rules/import/sigma", json={"content": content}).json()

    assert (second["created"], second["skipped"], second["rejected"]) == (0, 2, 2)
    first_ids = [item["rule_id"] for item in first["results"] if item["status"] == "created"]
    assert [item["reason"] for item in second["results"] if item["status"] == "skipped"] == [
        f"Already imported as {rule_id}." for rule_id in first_ids
    ]


def test_an_imported_rule_once_enabled_alerts_on_upload_with_its_technique(analyst):
    body = client.post("/custom-rules/import/sigma", json={"content": RULES_FILE.read_text(encoding="utf-8")}).json()
    brute = next(item["rule"] for item in body["results"] if item["status"] == "created")

    # Drafts never alert: an analyst enables the rule after reviewing it.
    assert client.patch(f"/custom-rules/{brute['id']}", json={"status": "ENABLED"}).status_code == 200
    upload = client.post(
        "/upload",
        files={"logfile": (EVENTS_FILE.name, BytesIO(EVENTS_FILE.read_bytes()), "text/plain")},
    )

    assert upload.status_code == 200, upload.text
    fired = [alert for alert in upload.json()["alerts"] if alert["rule"] == brute["rule_id"]]
    assert [(alert["source_ip"], alert["count"], alert["mitre_technique"]) for alert in fired] == [
        ("203.0.113.77", 5, "T1110.001"),
    ]


def test_dry_run_can_use_the_new_fields(analyst):
    client.post("/upload", files={"logfile": (EVENTS_FILE.name, BytesIO(EVENTS_FILE.read_bytes()), "text/plain")})

    response = client.post("/custom-rules/test", json={
        "name": "sudo shells",
        "conditions": [
            {"field": "process", "operator": "equals", "value": "sudo"},
            {"field": "command", "operator": "endswith", "values": ["/bin/bash", "/bin/sh"]},
        ],
    })

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["match_count"] >= 1
    assert all(match["process"] == "sudo" for match in body["matches"])


def test_import_rejects_oversized_or_empty_content_and_viewers(analyst, db_session):
    assert client.post("/custom-rules/import/sigma", json={"content": ""}).status_code == 422
    assert client.post("/custom-rules/import/sigma", json={"content": "x" * 262_145}).status_code == 422

    viewer_role = db_session.scalar(select(Role).where(Role.name == "Viewer"))
    if viewer_role is None:
        viewer_role = Role(name="Viewer", description="Viewer test role")
        db_session.add(viewer_role)
        db_session.commit()
    viewer = User(role_id=viewer_role.id, username=f"v-{uuid4().hex[:8]}", email=f"v-{uuid4().hex[:8]}@example.test",
                  password_hash="unused", is_active=True)
    viewer.role = viewer_role
    app.dependency_overrides[current_user] = lambda: viewer
    assert client.post("/custom-rules/import/sigma", json={"content": "title: x"}).status_code == 403
