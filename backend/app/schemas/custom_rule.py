from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

from app.detection.rules.custom_condition import KNOWN_FIELDS, OPERATORS_BY_TYPE, field_type

RULE_CATEGORIES = (
    "generic_detection",
    "threat_hunting",
    "emerging_threat",
    "compliance",
    "placeholder",
)
SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
STATUSES = ("DRAFT", "ENABLED", "DISABLED")
GROUP_BY_VALUES = ("ip_address", "username", "none")
WINDOW_SECONDS_VALUES = (300, 600, 1800, 3600, 86400)
ACTION_KEYS = ("create_alert", "notify_slack", "auto_incident", "suggest_playbook")
ActionValue = bool | dict[str, Any]
_TACTIC_RE = re.compile(r"^TA\d{4}$")


class ConditionPayload(BaseModel):
    field: str = Field(min_length=1, max_length=40)
    operator: str = Field(min_length=1, max_length=20)
    value: str = Field(min_length=1, max_length=200)

    @field_validator("field")
    @classmethod
    def field_must_be_known(cls, value: str) -> str:
        if value not in KNOWN_FIELDS:
            raise ValueError(
                f"Unknown field {value!r}. Allowed fields: {', '.join(sorted(KNOWN_FIELDS))}."
            )
        return value

    @model_validator(mode="after")
    def operator_must_match_field_type(self):
        allowed = OPERATORS_BY_TYPE[field_type(self.field)]
        if self.operator not in allowed:
            raise ValueError(
                f"Operator {self.operator!r} is not valid for field {self.field!r}. "
                f"Allowed operators: {', '.join(allowed)}."
            )
        return self


class CustomRuleBase(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    category: str = Field(default="generic_detection")
    severity: str = Field(default="medium")
    tactic: str | None = Field(default=None)
    conditions: list[ConditionPayload] = Field(min_length=1, max_length=10)
    group_by: str = Field(default="none")
    window_seconds: int = Field(default=600)
    actions: dict[str, ActionValue] = Field(default_factory=dict)
    dsl: str | None = Field(default=None, max_length=4000)

    @field_validator("name")
    @classmethod
    def name_must_not_be_blank(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("Rule name cannot be blank.")
        return cleaned

    @field_validator("category")
    @classmethod
    def category_must_be_known(cls, value: str) -> str:
        if value not in RULE_CATEGORIES:
            raise ValueError(f"Category must be one of: {', '.join(RULE_CATEGORIES)}.")
        return value

    @field_validator("severity")
    @classmethod
    def severity_must_be_known(cls, value: str) -> str:
        upper = value.strip().upper()
        if upper not in SEVERITIES:
            raise ValueError(f"Severity must be one of: {', '.join(SEVERITIES)}.")
        return upper

    @field_validator("tactic")
    @classmethod
    def tactic_must_look_like_mitre_code(cls, value: str | None) -> str | None:
        if value is None or value == "":
            return None
        cleaned = value.strip().upper()
        if not _TACTIC_RE.match(cleaned):
            raise ValueError('MITRE tactic must look like "TA0010".')
        return cleaned

    @field_validator("group_by")
    @classmethod
    def group_by_must_be_known(cls, value: str) -> str:
        if value not in GROUP_BY_VALUES:
            raise ValueError(f"Group by must be one of: {', '.join(GROUP_BY_VALUES)}.")
        return value

    @field_validator("window_seconds")
    @classmethod
    def window_seconds_must_be_known(cls, value: int) -> int:
        if value not in WINDOW_SECONDS_VALUES:
            raise ValueError(
                f"Window must be one of: {', '.join(str(v) for v in WINDOW_SECONDS_VALUES)} seconds."
            )
        return value

    @field_validator("actions")
    @classmethod
    def actions_must_be_known(cls, value: dict[str, ActionValue]) -> dict[str, ActionValue]:
        unknown = set(value) - set(ACTION_KEYS)
        if unknown:
            raise ValueError(f"Unknown action(s): {', '.join(sorted(unknown))}.")
        normalized: dict[str, ActionValue] = {}
        for key in ACTION_KEYS:
            action = value.get(key, False)
            normalized[key] = action if isinstance(action, dict) else bool(action)
        return normalized


class CustomRuleCreate(CustomRuleBase):
    status: str = Field(default="DRAFT")

    @field_validator("status")
    @classmethod
    def status_must_be_creatable(cls, value: str) -> str:
        upper = value.strip().upper()
        if upper not in ("DRAFT", "ENABLED"):
            raise ValueError('Status must be "DRAFT" or "ENABLED" on creation.')
        return upper


class CustomRuleUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    category: str | None = None
    severity: str | None = None
    tactic: str | None = None
    conditions: list[ConditionPayload] | None = Field(default=None, min_length=1, max_length=10)
    group_by: str | None = None
    window_seconds: int | None = None
    actions: dict[str, ActionValue] | None = None
    status: str | None = None
    dsl: str | None = Field(default=None, max_length=4000)

    @field_validator("name")
    @classmethod
    def name_must_not_be_blank(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("Rule name cannot be blank.")
        return cleaned

    @field_validator("category")
    @classmethod
    def category_must_be_known(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if value not in RULE_CATEGORIES:
            raise ValueError(f"Category must be one of: {', '.join(RULE_CATEGORIES)}.")
        return value

    @field_validator("severity")
    @classmethod
    def severity_must_be_known(cls, value: str | None) -> str | None:
        if value is None:
            return None
        upper = value.strip().upper()
        if upper not in SEVERITIES:
            raise ValueError(f"Severity must be one of: {', '.join(SEVERITIES)}.")
        return upper

    @field_validator("tactic")
    @classmethod
    def tactic_must_look_like_mitre_code(cls, value: str | None) -> str | None:
        if value is None or value == "":
            return None
        cleaned = value.strip().upper()
        if not _TACTIC_RE.match(cleaned):
            raise ValueError('MITRE tactic must look like "TA0010".')
        return cleaned

    @field_validator("group_by")
    @classmethod
    def group_by_must_be_known(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if value not in GROUP_BY_VALUES:
            raise ValueError(f"Group by must be one of: {', '.join(GROUP_BY_VALUES)}.")
        return value

    @field_validator("window_seconds")
    @classmethod
    def window_seconds_must_be_known(cls, value: int | None) -> int | None:
        if value is None:
            return None
        if value not in WINDOW_SECONDS_VALUES:
            raise ValueError(
                f"Window must be one of: {', '.join(str(v) for v in WINDOW_SECONDS_VALUES)} seconds."
            )
        return value

    @field_validator("actions")
    @classmethod
    def actions_must_be_known(cls, value: dict[str, ActionValue] | None) -> dict[str, ActionValue] | None:
        if value is None:
            return None
        unknown = set(value) - set(ACTION_KEYS)
        if unknown:
            raise ValueError(f"Unknown action(s): {', '.join(sorted(unknown))}.")
        normalized: dict[str, ActionValue] = {}
        for key, action in value.items():
            normalized[key] = action if isinstance(action, dict) else bool(action)
        return normalized

    @field_validator("status")
    @classmethod
    def status_must_be_known(cls, value: str | None) -> str | None:
        if value is None:
            return None
        upper = value.strip().upper()
        if upper not in STATUSES:
            raise ValueError(f"Status must be one of: {', '.join(STATUSES)}.")
        return upper

    @model_validator(mode="after")
    def require_update(self):
        if not self.model_fields_set:
            raise ValueError("Provide at least one custom rule field to update.")
        return self


class CustomRuleTestRequest(CustomRuleBase):
    """Dry-run payload: same shape as creation, minus persistence fields."""
