from __future__ import annotations

from app.detection.models import Alert, LogRecord
from app.detection.rules._audit import merge_audit_events
from app.detection.rules._host_alerts import host_alert, merge_host_alerts
from app.detection.rules._host_event_patterns import (
    DEFAULT_SECURITY_SERVICES,
    SECURITY_DISABLE_COMMANDS,
    extract_stopped_service,
    match_command,
    stopped_service_in_command,
)
from app.detection.rules.base import BaseRule


class SecurityControlDisabledRule(BaseRule):
    """Fires when a host security control is turned off. Three evidence paths:

    - systemd reports stopping a watched security service (syslog);
    - a command that flushes the firewall, disables ufw/nftables, sets
      SELinux permissive, tears down AppArmor, or stops a watched service —
      seen as a sudo `COMMAND=` (syslog) or an audit EXECVE record;
    - an audit MAC_STATUS record with enforcing=0.

    The watched service list is configurable (`allowlist`), not hardcoded.
    Commands run without sudo and without auditd exec logging are invisible
    to this rule.
    """

    name = "security_control_disabled"
    description = "A firewall, MAC policy, or security agent was disabled."
    severity = "HIGH"
    mitre_technique = "T1562"
    entity_type = "host"
    confidence = 75

    def __init__(self, cooldown_seconds: int = 900, allowlist: list[str] | None = None):
        self.cooldown_seconds = cooldown_seconds
        self.allowlist = allowlist
        self._watched = tuple(s.lower() for s in allowlist) if allowlist else DEFAULT_SECURITY_SERVICES

    def _alert(self, record_like, lines, reason, evidence) -> Alert:
        return host_alert(
            self,
            hostname=record_like.hostname,
            timestamp=record_like.timestamp,
            line_numbers=lines,
            username=record_like.username,
            prefix="Security control disabled",
            reason=reason,
            evidence=evidence,
        )

    def analyze(self, records: list[LogRecord], db=None) -> list[Alert]:
        alerts: list[Alert] = []

        for record in records:
            if record.audit_event_id:
                continue  # handled once per merged audit event below
            service = extract_stopped_service(record.process, record.message)
            if service and any(watched in service.lower() for watched in self._watched):
                alerts.append(self._alert(record, [record.line_number], f"service '{service}' was stopped", {"service": service}))
                continue
            reason = match_command(record.command, SECURITY_DISABLE_COMMANDS)
            if reason is None:
                target = stopped_service_in_command(record.command, self._watched)
                reason = f"service '{target}' stopped by command" if target else None
            if reason:
                alerts.append(self._alert(record, [record.line_number], reason, {"command": record.command}))

        for event in merge_audit_events(records):
            reason = None
            evidence: dict = {"audit_event_id": event.event_id}
            if "MAC_STATUS" in event.types and event.fields.get("enforcing") == "0":
                reason = "SELinux enforcement turned off (MAC_STATUS enforcing=0)"
            else:
                reason = match_command(event.command, SECURITY_DISABLE_COMMANDS)
                if reason is None:
                    target = stopped_service_in_command(event.command, self._watched)
                    reason = f"service '{target}' stopped by command" if target else None
                if reason:
                    evidence["command"] = event.command
            if reason:
                alerts.append(self._alert(event, event.line_numbers, reason, evidence))

        return merge_host_alerts(self, alerts, self.cooldown_seconds)
