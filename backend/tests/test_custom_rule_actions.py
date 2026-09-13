from __future__ import annotations

from uuid import uuid4

from sqlalchemy import select

from app.models.alert import Alert
from app.models.custom_rule import CustomRule
from app.models.incident import Incident
from app.repositories.custom_rule_action_repository import apply_custom_rule_actions


def make_rule(db_session, *, actions: dict, category: str = "threat_hunting") -> CustomRule:
    rule = CustomRule(
        rule_id=f"R-{uuid4().int % 100000}",
        name="Repeated custom signal",
        category=category,
        severity="HIGH",
        tactic="TA0010",
        conditions=[{"field": "status", "operator": "equals", "value": "FAILED"}],
        group_by="ip_address",
        window_seconds=3600,
        actions=actions,
        status="ENABLED",
    )
    db_session.add(rule)
    db_session.flush()
    return rule


def make_alert(db_session, rule: CustomRule, *, count: int = 3, window_seconds: int = 3600) -> Alert:
    alert = Alert(
        upload_id=uuid4(),
        rule=rule.rule_id,
        title=rule.name,
        severity=rule.severity,
        status="NEW",
        source_ip="203.0.113.10",
        username="root",
        event_count=count,
        time_window_seconds=window_seconds,
        description="Custom rule matched.",
        matched_line_numbers=[1, 2, 3][:count],
    )
    db_session.add(alert)
    db_session.flush()
    return alert


def test_custom_rule_actions_create_incident_and_link_playbook(db_session):
    rule = make_rule(
        db_session,
        actions={
            "create_alert": True,
            "auto_incident": True,
            "suggest_playbook": True,
            "notify_slack": False,
        },
    )
    alert = make_alert(db_session, rule)

    summary = apply_custom_rule_actions(db_session, alerts=[alert], custom_rules=[rule])

    incident = db_session.scalar(select(Incident).where(Incident.source_alert_id == alert.id))
    assert summary["auto_incidents_created"] == 1
    assert incident is not None
    assert alert.status == "ESCALATED"
    assert alert.response_playbook["id"] == "PB-02"
    assert incident.response_playbook["id"] == "PB-02"
    assert alert.action_results["auto_incident"]["status"] == "created"
    assert alert.action_results["suggest_playbook"]["playbook_id"] == "PB-02"


def test_auto_incident_respects_default_threshold(db_session):
    rule = make_rule(
        db_session,
        actions={"create_alert": True, "auto_incident": True},
    )
    alert = make_alert(db_session, rule, count=2)

    summary = apply_custom_rule_actions(db_session, alerts=[alert], custom_rules=[rule])

    assert summary["auto_incidents_created"] == 0
    assert db_session.scalar(select(Incident).where(Incident.source_alert_id == alert.id)) is None
    assert alert.status == "NEW"
    assert alert.action_results["auto_incident"]["status"] == "threshold_not_met"


def test_slack_notification_uses_injected_dispatcher(db_session):
    rule = make_rule(
        db_session,
        actions={
            "create_alert": True,
            "notify_slack": True,
            "suggest_playbook": True,
        },
    )
    alert = make_alert(db_session, rule)
    calls = []

    def fake_dispatcher(**kwargs):
        calls.append(kwargs)
        return {"status": "sent", "status_code": 200}

    summary = apply_custom_rule_actions(
        db_session,
        alerts=[alert],
        custom_rules=[rule],
        slack_webhook_url="https://hooks.slack.test/services/example",
        slack_dispatcher=fake_dispatcher,
    )

    assert summary["slack_notifications"]["sent"] == 1
    assert calls[0]["webhook_url"].startswith("https://hooks.slack.test/")
    assert calls[0]["payload"]["attachments"][0]["fields"][-1]["title"] == "Playbook"
    assert alert.action_results["notify_slack"]["status"] == "sent"
