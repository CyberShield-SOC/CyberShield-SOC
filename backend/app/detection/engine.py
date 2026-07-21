from __future__ import annotations

from app.detection.models import Alert, LogRecord
from app.detection.rules.base import BaseRule
from app.detection.rules.brute_force import BruteForceLoginRule
from app.detection.rules.credential_stuffing import CredentialStuffingRule
from app.detection.rules.invalid_user import InvalidUserRule
from app.detection.rules.password_spraying import PasswordSprayingRule
from app.detection.rules.port_scan import PortScanRule
from app.detection.rules.sudo_failure import SudoFailureRule


def _default_rules() -> list[BaseRule]:
    return [
        BruteForceLoginRule(),
        InvalidUserRule(),
        SudoFailureRule(),
        PasswordSprayingRule(),
        CredentialStuffingRule(),
        PortScanRule(),
    ]


class DetectionEngine:
    """Runs all registered rules against a list of LogRecords and aggregates alerts."""

    def __init__(self, rules: list[BaseRule] | None = None):
        self.rules: list[BaseRule] = rules if rules is not None else _default_rules()

    def run(self, records: list[LogRecord]) -> list[Alert]:
        alerts: list[Alert] = []
        for rule in self.rules:
            alerts.extend(rule.analyze(records))
        return alerts
