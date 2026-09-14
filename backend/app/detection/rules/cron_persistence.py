from __future__ import annotations

from app.detection.models import Alert, LogRecord
from app.detection.rules._host_alerts import host_alert, merge_host_alerts
from app.detection.rules._host_event_patterns import extract_cron_persistence
from app.detection.rules.base import BaseRule


class CronPersistenceRule(BaseRule):
    """Fires when a crontab is edited or a systemd timer is started —
    common persistence mechanisms. Syslog sources only.

    Sysadmins edit cron routinely, so this defaults to MEDIUM severity and
    one alert per host per cooldown rather than per edit, per the "low false
    positives on normal admin activity" requirement.
    """

    name = "cron_persistence"
    description = "A cron entry or systemd timer was created or modified."
    severity = "MEDIUM"
    mitre_technique = "T1053.003"
    entity_type = "host"
    confidence = 55

    def __init__(self, cooldown_seconds: int = 1800):
        self.cooldown_seconds = cooldown_seconds

    def analyze(self, records: list[LogRecord], db=None) -> list[Alert]:
        findings = []
        for record in records:
            detail = extract_cron_persistence(record.process, record.message)
            if detail is None:
                continue
            findings.append(host_alert(
                self,
                hostname=record.hostname,
                timestamp=record.timestamp,
                line_numbers=[record.line_number],
                username=record.username,
                prefix="Scheduled-task persistence",
                reason=detail,
            ))
        return merge_host_alerts(self, findings, self.cooldown_seconds)
