from __future__ import annotations

from app.detection._ts import parse_ts, ts_to_str
from app.detection.models import Alert, LogRecord
from app.detection.rules.base import BaseRule

DEFAULT_ROOT_ACCOUNTS = ("root",)


class DirectRootLoginRule(BaseRule):
    """Fires on a successful direct login to a superuser account.

    Implementable with existing fields (username/status/event_type) on any
    source — no syslog-specific fields needed. The watched account name(s)
    are configurable (`allowlist`) since not every OS/convention calls its
    superuser "root".
    """

    name = "direct_root_login"
    description = "A successful direct login to a superuser account."
    severity = "HIGH"
    mitre_technique = "T1078.003"
    entity_type = "account"
    confidence = 80

    def __init__(self, cooldown_seconds: int = 0, allowlist: list[str] | None = None):
        self.cooldown_seconds = cooldown_seconds
        self.allowlist = allowlist
        self._root_accounts = {a.lower() for a in (allowlist or DEFAULT_ROOT_ACCOUNTS)}

    def analyze(self, records: list[LogRecord], db=None) -> list[Alert]:
        alerts: list[Alert] = []
        for record in records:
            if (
                record.event_type == "login_attempt"
                and record.status == "SUCCESS"
                and record.username
                and record.username.lower() in self._root_accounts
                and record.ip_address
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
                        f"Direct successful login to '{record.username}' from {record.ip_address}."
                    ),
                    matched_line_numbers=[record.line_number],
                    mitre_technique=self.mitre_technique,
                    confidence=self.confidence,
                    entity_type=self.entity_type,
                    entity_id=record.username,
                ))
        return alerts
