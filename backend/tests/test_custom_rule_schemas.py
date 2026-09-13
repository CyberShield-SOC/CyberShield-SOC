"""Validation coverage for the custom-rule request schemas: field/operator
whitelisting keeps a saved rule from ever referencing a non-existent event
attribute (e.g. the frontend mock's old "bytes_out"/"host" fields).
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.no_db

from pydantic import ValidationError

from app.schemas.custom_rule import CustomRuleCreate, CustomRuleUpdate


def _base_payload(**overrides):
    payload = {
        "name": "Off-hours privilege escalation",
        "category": "generic_detection",
        "severity": "high",
        "tactic": "TA0010",
        "conditions": [
            {"field": "event_type", "operator": "equals", "value": "privilege_escalation"},
        ],
        "group_by": "ip_address",
        "window_seconds": 600,
        "actions": {"create_alert": True, "notify_slack": False},
        "status": "DRAFT",
    }
    payload.update(overrides)
    return payload


def test_valid_payload_is_accepted():
    rule = CustomRuleCreate.model_validate(_base_payload())
    assert rule.severity == "HIGH"
    assert rule.actions["auto_incident"] is False


def test_actions_allow_future_nested_configuration():
    rule = CustomRuleCreate.model_validate(
        _base_payload(
            actions={
                "create_alert": True,
                "auto_incident": {"enabled": True, "threshold_count": 4},
                "suggest_playbook": {"enabled": True, "playbook_id": "PB-09"},
            }
        )
    )
    assert rule.actions["auto_incident"]["threshold_count"] == 4


def test_unknown_field_is_rejected():
    payload = _base_payload(conditions=[{"field": "bytes_out", "operator": "equals", "value": "500"}])
    with pytest.raises(ValidationError, match="Unknown field"):
        CustomRuleCreate.model_validate(payload)


def test_operator_mismatched_with_field_type_is_rejected():
    payload = _base_payload(conditions=[{"field": "port", "operator": "contains", "value": "22"}])
    with pytest.raises(ValidationError, match="not valid for field"):
        CustomRuleCreate.model_validate(payload)


def test_unknown_category_is_rejected():
    with pytest.raises(ValidationError, match="Category must be one of"):
        CustomRuleCreate.model_validate(_base_payload(category="not_a_category"))


def test_unsupported_window_is_rejected():
    with pytest.raises(ValidationError, match="Window must be one of"):
        CustomRuleCreate.model_validate(_base_payload(window_seconds=42))


def test_unknown_action_key_is_rejected():
    payload = _base_payload(actions={"delete_everything": True})
    with pytest.raises(ValidationError, match="Unknown action"):
        CustomRuleCreate.model_validate(payload)


def test_status_defaults_to_draft_and_rejects_disabled_on_create():
    with pytest.raises(ValidationError, match='"DRAFT" or "ENABLED"'):
        CustomRuleCreate.model_validate(_base_payload(status="DISABLED"))


def test_update_requires_at_least_one_field():
    with pytest.raises(ValidationError, match="at least one custom rule field"):
        CustomRuleUpdate.model_validate({})


def test_update_allows_status_only_change():
    update = CustomRuleUpdate.model_validate({"status": "enabled"})
    assert update.status == "ENABLED"
    assert update.name is None
