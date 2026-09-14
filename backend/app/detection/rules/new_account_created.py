from __future__ import annotations

from app.detection.models import Alert, LogRecord
from app.detection.rules._host_alerts import host_alert, merge_host_alerts
from app.detection.rules._host_event_patterns import extract_created_account
from app.detection.rules.base import BaseRule


class NewAccountCreatedRule(BaseRule):
    """Fires on a useradd/adduser event — a new OS account was created.

    Syslog sources only: it needs the `process`/`message` fields
    syslog_parser.py extracts. Several accounts created on one host within
    cooldown_seconds are reported as one alert listing every account, and
    repeat alerts for that host inside the cooldown are suppressed, so a
    sysadmin provisioning a team produces one alert, not one per account.
    """

    name = "new_account_created"
    description = "A new OS account was created (useradd/adduser)."
    severity = "HIGH"
    mitre_technique = "T1136"
    entity_type = "host"
    confidence = 75

    def __init__(self, cooldown_seconds: int = 1800):
        self.cooldown_seconds = cooldown_seconds

    def analyze(self, records: list[LogRecord], db=None) -> list[Alert]:
        findings = []
        for record in records:
            created_user = extract_created_account(record.process, record.message)
            if created_user is None:
                continue
            findings.append(host_alert(
                self,
                hostname=record.hostname,
                timestamp=record.timestamp,
                line_numbers=[record.line_number],
                username=created_user,
                prefix="New account created",
                reason=f"'{created_user}' via {record.process}",
                evidence={"account": created_user},
            ))
        return merge_host_alerts(self, findings, self.cooldown_seconds)
