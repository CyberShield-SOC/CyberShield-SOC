from __future__ import annotations

from collections.abc import Mapping

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.detection.engine import _RULE_CLASSES
from app.detection.models import RuleConfig
from app.models.detection_rule_setting import DetectionRuleSetting

_OVERRIDE_FIELDS = ("threshold", "fail_threshold", "window_seconds", "success_window_seconds")


class DetectionRuleNotFoundError(Exception):
    """Raised when the requested rule name is not a registered built-in rule."""


def known_rule_names() -> set[str]:
    """Every built-in rule name the DetectionEngine can run, regardless of config."""

    return {rule_cls().name for rule_cls in _RULE_CLASSES}


def list_rule_settings(db: Session) -> dict[str, DetectionRuleSetting]:
    rows = db.scalars(select(DetectionRuleSetting)).all()
    return {row.rule_name: row for row in rows}


def effective_rule_configs(
    db: Session,
    env_config: Mapping[str, RuleConfig | dict] | None = None,
) -> dict[str, RuleConfig]:
    """Merge, per rule, the class default <- env config <- DB override.

    Each layer only overrides the fields it actually sets, so an operator can
    change just a threshold in the UI without losing an env-configured
    window, and vice versa.
    """

    env_config = env_config or {}
    settings_by_name = list_rule_settings(db)
    merged: dict[str, RuleConfig] = {}

    for rule_cls in _RULE_CLASSES:
        default_rule = rule_cls()
        config = default_rule.config.model_dump()

        env_override = env_config.get(default_rule.name)
        if env_override is not None:
            env_dict = (
                env_override.model_dump(exclude_none=True)
                if isinstance(env_override, RuleConfig)
                else {k: v for k, v in dict(env_override).items() if v is not None}
            )
            config.update(env_dict)

        row = settings_by_name.get(default_rule.name)
        if row is not None:
            config["enabled"] = row.enabled
            for field in _OVERRIDE_FIELDS:
                value = getattr(row, field)
                if value is not None:
                    config[field] = value

        merged[default_rule.name] = RuleConfig.model_validate(config)

    return merged


def upsert_rule_setting(
    db: Session,
    *,
    rule_name: str,
    updates: dict,
    updated_by: int | None,
) -> DetectionRuleSetting:
    valid_names = known_rule_names()
    if rule_name not in valid_names:
        raise DetectionRuleNotFoundError(f"Unknown detection rule '{rule_name}'.")

    row = db.get(DetectionRuleSetting, rule_name)
    if row is None:
        row = DetectionRuleSetting(rule_name=rule_name)
        db.add(row)

    if "enabled" in updates:
        row.enabled = updates["enabled"]
    for field in _OVERRIDE_FIELDS:
        if field in updates:
            setattr(row, field, updates[field])
    row.updated_by = updated_by

    db.flush()
    return row
