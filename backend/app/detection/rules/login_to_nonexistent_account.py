from __future__ import annotations

from app.detection._ts import parse_ts, ts_to_str
from app.detection.models import Alert, LogRecord
from app.detection.rules.base import BaseRule


class LoginToNonexistentAccountRule(BaseRule):
    """Fires on a failed login attempt against a configured decommissioned/
    disabled account name.

    Auth logs cannot distinguish "this username never existed" from "this
    username was deleted/disabled" — sshd emits the identical message either
    way — so this only works against a maintained roster (`allowlist`) of
    names you know are decommissioned. With no roster configured, this rule
    matches nothing. General unknown-username probing (never-existed names)
    is already covered by invalid_user_enumeration; this rule is narrower
    and deliberately overlaps it for the specific, known-decommissioned case.
    """

    name = "login_to_nonexistent_account"
    description = "A failed login attempt targeted a known decommissioned/disabled account."
    severity = "MEDIUM"
    mitre_technique = "T1078"
    entity_type = "account"
    confidence = 60

    def __init__(self, cooldown_seconds: int = 0, allowlist: list[str] | None = None):
        self.cooldown_seconds = cooldown_seconds
        self.allowlist = allowlist
        self._decommissioned = {a.lower() for a in (allowlist or ())}

    def analyze(self, records: list[LogRecord], db=None) -> list[Alert]:
        if not self._decommissioned:
            return []

        alerts: list[Alert] = []
        for record in records:
            if (
                record.event_type == "login_attempt"
                and record.status == "FAILED"
                and record.username
                and record.username.lower() in self._decommissioned
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
                        f"Login attempt against decommissioned account '{record.username}'"
                        f" from {record.ip_address or 'an unknown source'}."
                    ),
                    matched_line_numbers=[record.line_number],
                    mitre_technique=self.mitre_technique,
                    confidence=self.confidence,
                    entity_type=self.entity_type,
                    entity_id=record.username,
                ))
        return alerts
