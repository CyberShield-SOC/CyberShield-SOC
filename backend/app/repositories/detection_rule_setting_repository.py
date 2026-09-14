from __future__ import annotations

from collections.abc import Mapping

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.detection.engine import _RULE_CLASSES
from app.detection.models import RuleConfig
from app.models.detection_rule_setting import DetectionRuleSetting

_OVERRIDE_FIELDS = (
    "threshold",
    "fail_threshold",
    "window_seconds",
    "success_window_seconds",
    "cooldown_seconds",
    "confidence",
    "allowlist",
    "start_hour",
    "end_hour",
    "params",
)


class DetectionRuleNotFoundError(Exception):
    """Raised when the requested rule name is not a registered built-in rule."""


class DetectionRuleSettingError(ValueError):
    """Raised when an update names a setting the rule doesn't support."""


def rule_classes_by_name() -> dict[str, type]:
    return {rule_cls().name: rule_cls for rule_cls in _RULE_CLASSES}


def known_rule_names() -> set[str]:
    """Every built-in rule name the DetectionEngine can run, regardless of config."""

    return set(rule_classes_by_name())


def list_rule_settings(db: Session) -> dict[str, DetectionRuleSetting]:
    rows = db.scalars(select(DetectionRuleSetting)).all()
    return {row.rule_name: row for row in rows}


def _apply_layer(config: dict, layer: Mapping) -> None:
    for field, value in layer.items():
        if value is None:
            continue
        if field == "params":
            # Params merge key by key so overriding one tunable keeps the rest.
            config["params"] = {**(config.get("params") or {}), **dict(value)}
        else:
            config[field] = value


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
            _apply_layer(
                config,
                env_override.model_dump(exclude_none=True)
                if isinstance(env_override, RuleConfig)
                else dict(env_override),
            )

        row = settings_by_name.get(default_rule.name)
        if row is not None:
            config["enabled"] = row.enabled
            _apply_layer(config, {field: getattr(row, field) for field in _OVERRIDE_FIELDS})

        merged[default_rule.name] = RuleConfig.model_validate(config)

    return merged


def validate_rule_updates(rule_name: str, updates: dict) -> None:
    """Reject settings the named rule would silently ignore."""

    rule_cls = rule_classes_by_name().get(rule_name)
    if rule_cls is None:
        raise DetectionRuleNotFoundError(f"Unknown detection rule '{rule_name}'.")

    tunables = set(rule_cls.tunables())
    unsupported = sorted(field for field in updates if field not in tunables)
    if unsupported:
        raise DetectionRuleSettingError(
            f"Rule '{rule_name}' does not use: {', '.join(unsupported)}."
        )

    params = updates.get("params")
    if params:
        unknown = sorted(set(params) - set(rule_cls.DEFAULT_PARAMS))
        if unknown:
            raise DetectionRuleSettingError(
                f"Rule '{rule_name}' has no parameter(s): {', '.join(unknown)}."
            )


def upsert_rule_setting(
    db: Session,
    *,
    rule_name: str,
    updates: dict,
    updated_by: int | None,
) -> DetectionRuleSetting:
    validate_rule_updates(rule_name, updates)

    row = db.get(DetectionRuleSetting, rule_name)
    if row is None:
        row = DetectionRuleSetting(rule_name=rule_name)
        db.add(row)

    if "enabled" in updates:
        row.enabled = updates["enabled"]
    for field in _OVERRIDE_FIELDS:
        if field not in updates:
            continue
        if field == "params" and updates[field] is not None:
            row.params = {**(row.params or {}), **updates[field]}
        else:
            setattr(row, field, updates[field])
    row.updated_by = updated_by

    db.flush()
    return row
