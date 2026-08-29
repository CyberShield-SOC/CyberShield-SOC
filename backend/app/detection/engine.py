from __future__ import annotations

from collections.abc import Mapping
from inspect import signature

from app.detection.models import Alert, LogRecord, RuleConfig, RuleMetadata
from app.detection.rules.base import BaseRule
from app.detection.rules.brute_force import BruteForceLoginRule
from app.detection.rules.credential_stuffing import CredentialStuffingRule
from app.detection.rules.invalid_user import InvalidUserRule
from app.detection.rules.password_spraying import PasswordSprayingRule
from app.detection.rules.port_scan import PortScanRule
from app.detection.rules.sudo_failure import SudoFailureRule


def _rule_from_config(rule_cls: type[BaseRule], config: RuleConfig) -> BaseRule | None:
    if not config.enabled:
        return None

    kwargs = {
        field: value
        for field, value in config.model_dump(exclude_none=True).items()
        if field != "enabled" and field in signature(rule_cls).parameters
    }
    return rule_cls(**kwargs)


_RULE_CLASSES: tuple[type[BaseRule], ...] = (
    BruteForceLoginRule,
    InvalidUserRule,
    SudoFailureRule,
    PasswordSprayingRule,
    CredentialStuffingRule,
    PortScanRule,
)


def _default_rules() -> list[BaseRule]:
    return [rule_cls() for rule_cls in _RULE_CLASSES]


class DetectionEngine:
    """Runs all registered rules against a list of LogRecords and aggregates alerts."""

    def __init__(self, rules: list[BaseRule] | None = None):
        self.rules: list[BaseRule] = rules if rules is not None else _default_rules()

    @classmethod
    def from_config(
        cls,
        configs: Mapping[str, RuleConfig | dict] | None = None,
    ) -> "DetectionEngine":
        """Build Detection Engine v2 with rule-name keyed threshold overrides."""

        configs = configs or {}
        rules: list[BaseRule] = []

        for rule_cls in _RULE_CLASSES:
            default_rule = rule_cls()
            raw_config = configs.get(default_rule.name)
            config = (
                RuleConfig.model_validate(raw_config)
                if raw_config is not None
                else default_rule.config
            )
            rule = _rule_from_config(rule_cls, config)
            if rule is not None:
                rules.append(rule)

        return cls(rules=rules)

    def rule_metadata(self) -> list[RuleMetadata]:
        """Expose Detection Engine v2 rule names and active thresholds."""

        return [rule.metadata() for rule in self.rules]

    def run(self, records: list[LogRecord]) -> list[Alert]:
        alerts: list[Alert] = []
        for rule in self.rules:
            alerts.extend(rule.analyze(records))
        return alerts
