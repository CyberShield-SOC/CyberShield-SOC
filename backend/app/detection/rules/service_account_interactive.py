from __future__ import annotations

from app.detection._ts import parse_ts, ts_to_str
from app.detection.models import Alert, LogRecord
from app.detection.rules.base import BaseRule


class ServiceAccountInteractiveRule(BaseRule):
    """Fires when a configured service/system account completes a
    successful interactive login.

    There is no universal default list of service-account names — unlike
    DirectRootLoginRule's "root", this varies entirely by deployment. With
    no `allowlist` configured, this rule matches nothing (fails safe, does
    not guess). Configure `allowlist` with your service accounts
    (e.g. ["www-data", "postgres", "backup-svc"]) to enable it.
    """

    name = "service_account_interactive"
    description = "A configured service/system account was used for an interactive login."
    severity = "HIGH"
    mitre_technique = "T1078"
    entity_type = "account"
    confidence = 70

    def __init__(self, cooldown_seconds: int = 0, allowlist: list[str] | None = None):
        self.cooldown_seconds = cooldown_seconds
        self.allowlist = allowlist
        self._service_accounts = {a.lower() for a in (allowlist or ())}

    def analyze(self, records: list[LogRecord], db=None) -> list[Alert]:
        if not self._service_accounts:
            return []

        alerts: list[Alert] = []
        for record in records:
            if (
                record.event_type == "login_attempt"
                and record.status == "SUCCESS"
                and record.username
                and record.username.lower() in self._service_accounts
            ):
                ts = parse_ts(record.timestamp)
                seen = ts_to_str(ts) if ts else record.timestamp
                alerts.append(Alert(
                    rule=self.name,
                    severity=self.severity,
                    source_ip=record.ip_address,
                    username=record.username,
                    hostname=record.hostname,
                    count=1,
                    time_window_seconds=self.cooldown_seconds,
                    first_seen=seen,
                    last_seen=seen,
                    description=(
                        f"Service account '{record.username}' completed an interactive login."
                    ),
                    matched_line_numbers=[record.line_number],
                    mitre_technique=self.mitre_technique,
                    confidence=self.confidence,
                    entity_type=self.entity_type,
                    entity_id=record.username,
                ))
        return alerts
