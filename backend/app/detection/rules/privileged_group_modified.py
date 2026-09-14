from __future__ import annotations

from app.detection.models import Alert, LogRecord
from app.detection.rules._host_alerts import host_alert, merge_host_alerts
from app.detection.rules._host_event_patterns import (
    DEFAULT_PRIVILEGED_GROUPS,
    extract_privileged_group_addition,
)
from app.detection.rules.base import BaseRule


class PrivilegedGroupModifiedRule(BaseRule):
    """Fires when an account is added to a configured privileged group
    (usermod/gpasswd). Syslog sources only — see NewAccountCreatedRule.

    The privileged-group list is configurable (`allowlist`) rather than
    hardcoded, since "privileged" varies by distro/deployment.
    """

    name = "privileged_group_modified"
    description = "An account was added to a privileged group (sudo/wheel/admin/...)."
    severity = "HIGH"
    mitre_technique = "T1098"
    entity_type = "host"
    confidence = 80

    def __init__(
        self,
        cooldown_seconds: int = 1800,
        allowlist: list[str] | None = None,
    ):
        self.cooldown_seconds = cooldown_seconds
        self.allowlist = allowlist
        self._privileged_groups = tuple(allowlist) if allowlist else DEFAULT_PRIVILEGED_GROUPS

    def analyze(self, records: list[LogRecord], db=None) -> list[Alert]:
        findings = []
        for record in records:
            match = extract_privileged_group_addition(
                record.process, record.message, privileged_groups=self._privileged_groups
            )
            if match is None:
                continue
            username, group = match
            findings.append(host_alert(
                self,
                hostname=record.hostname,
                timestamp=record.timestamp,
                line_numbers=[record.line_number],
                username=username,
                prefix="Privileged group modified",
                reason=f"'{username}' added to '{group}'",
                evidence={"account": username, "group": group},
            ))
        return merge_host_alerts(self, findings, self.cooldown_seconds)
