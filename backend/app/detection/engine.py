from __future__ import annotations

from collections.abc import Mapping
from inspect import signature
from typing import TYPE_CHECKING

from app.detection.models import Alert, LogRecord, RuleConfig, RuleMetadata
from app.detection.rules.base import BaseRule
from app.detection.rules.behavioral_anomaly_egress import BehavioralAnomalyEgressRule
from app.detection.rules.behavioral_anomaly_login import BehavioralAnomalyLoginRule
from app.detection.rules.brute_force import BruteForceLoginRule
from app.detection.rules.credential_stuffing import CredentialStuffingRule
from app.detection.rules.cron_persistence import CronPersistenceRule
from app.detection.rules.direct_root_login import DirectRootLoginRule
from app.detection.rules.dns_tunneling import DnsTunnelingRule
from app.detection.rules.dormant_account_activity import DormantAccountActivityRule
from app.detection.rules.egress_volume_anomaly import EgressVolumeAnomalyRule
from app.detection.rules.first_seen_geo_asn import FirstSeenGeoAsnRule
from app.detection.rules.host_log_silence import HostLogSilenceRule
from app.detection.rules.host_sweep import HostSweepRule
from app.detection.rules.impossible_travel import ImpossibleTravelRule
from app.detection.rules.invalid_user import InvalidUserRule
from app.detection.rules.lateral_movement_chain import LateralMovementChainRule
from app.detection.rules.log_tampering import LogTamperingRule
from app.detection.rules.login_to_nonexistent_account import LoginToNonexistentAccountRule
from app.detection.rules.multi_ip_login import MultiIPLoginRule
from app.detection.rules.new_account_created import NewAccountCreatedRule
from app.detection.rules.off_hours_login import OffHoursLoginRule
from app.detection.rules.outbound_beaconing import OutboundBeaconingRule
from app.detection.rules.password_spraying import PasswordSprayingRule
from app.detection.rules.port_scan import PortScanRule
from app.detection.rules.privileged_group_modified import PrivilegedGroupModifiedRule
from app.detection.rules.security_control_disabled import SecurityControlDisabledRule
from app.detection.rules.service_account_interactive import ServiceAccountInteractiveRule
from app.detection.rules.ssh_key_added import SshKeyAddedRule
from app.detection.rules.sudo_failure import SudoFailureRule
from app.detection.rules.sudo_after_login import SudoAfterLoginRule
from app.detection.rules.threat_intel_match import ThreatIntelMatchRule

if TYPE_CHECKING:
    from sqlalchemy.orm import Session


def _rule_from_config(rule_cls: type[BaseRule], config: RuleConfig) -> BaseRule | None:
    if not config.enabled:
        return None

    kwargs = {
        field: value
        for field, value in config.model_dump(exclude_none=True).items()
        if field != "enabled" and field in signature(rule_cls).parameters
    }
    rule = rule_cls(**kwargs)
    # confidence is a class attribute on every rule rather than an __init__
    # parameter, so apply an override directly.
    if config.confidence is not None:
        rule.confidence = config.confidence
    return rule


_RULE_CLASSES: tuple[type[BaseRule], ...] = (
    BruteForceLoginRule,
    InvalidUserRule,
    SudoFailureRule,
    PasswordSprayingRule,
    CredentialStuffingRule,
    PortScanRule,
    MultiIPLoginRule,
    SudoAfterLoginRule,
    # Group A — post-compromise and log integrity
    NewAccountCreatedRule,
    PrivilegedGroupModifiedRule,
    CronPersistenceRule,
    SecurityControlDisabledRule,
    LogTamperingRule,
    SshKeyAddedRule,
    HostLogSilenceRule,
    # Group B — identity context
    DirectRootLoginRule,
    ServiceAccountInteractiveRule,
    LoginToNonexistentAccountRule,
    OffHoursLoginRule,
    DormantAccountActivityRule,
    ImpossibleTravelRule,
    FirstSeenGeoAsnRule,
    # Group C — network and lateral movement
    LateralMovementChainRule,
    HostSweepRule,
    OutboundBeaconingRule,
    DnsTunnelingRule,
    EgressVolumeAnomalyRule,
    ThreatIntelMatchRule,
    # Group D — machine-learning pilots (docs/ml/isolation_forest_feasibility.md)
    BehavioralAnomalyLoginRule,
    BehavioralAnomalyEgressRule,
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

    @staticmethod
    def rule_from_config(rule_cls: type[BaseRule], config: RuleConfig) -> BaseRule | None:
        return _rule_from_config(rule_cls, config)

    def rule_metadata(self) -> list[RuleMetadata]:
        """Expose Detection Engine v2 rule names and active thresholds."""

        return [rule.metadata() for rule in self.rules]

    def run(self, records: list[LogRecord], db: "Session | None" = None) -> list[Alert]:
        """
        Run every registered rule against `records`.

        `db` is only used by the handful of rules that need cross-upload
        history (see app/repositories/baseline_repository.py) — most rules
        ignore it and stay fully stateless. Passing None disables those
        rules' baseline lookups; they simply produce no alerts rather than
        erroring (see e.g. DormantAccountActivityRule.analyze).
        """

        alerts: list[Alert] = []
        for rule in self.rules:
            alerts.extend(rule.analyze(records, db))
        return alerts
