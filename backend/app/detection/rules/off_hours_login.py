from __future__ import annotations

from datetime import timezone

from app.detection._ts import parse_ts, ts_to_str
from app.detection.models import Alert, LogRecord
from app.detection.rules.base import BaseRule


class OffHoursLoginRule(BaseRule):
    """Fires on a successful login outside a configured business-hours window.

    This is a STATIC configured window (start_hour/end_hour, evaluated
    against each timestamp's UTC hour), not a learned per-account baseline —
    a learned baseline needs persistent per-account history this engine
    doesn't maintain today. If your log timestamps aren't already UTC,
    configure start_hour/end_hour in the same timezone your logs use.
    """

    name = "off_hours_login"
    description = "A successful login occurred outside the configured business-hours window."
    severity = "LOW"
    mitre_technique = "T1078"
    entity_type = "account"
    confidence = 40

    def __init__(
        self,
        cooldown_seconds: int = 0,
        start_hour: int = 6,
        end_hour: int = 20,
    ):
        self.cooldown_seconds = cooldown_seconds
        self.start_hour = start_hour
        self.end_hour = end_hour

    def _is_off_hours(self, hour: int) -> bool:
        if self.start_hour == self.end_hour:
            return False  # a zero-width window means "no restriction"
        if self.start_hour < self.end_hour:
            return not (self.start_hour <= hour < self.end_hour)
        # Wraps midnight (e.g. 22 -> 6 for an overnight shift).
        return not (hour >= self.start_hour or hour < self.end_hour)

    def analyze(self, records: list[LogRecord], db=None) -> list[Alert]:
        alerts: list[Alert] = []
        for record in records:
            if not (
                record.event_type == "login_attempt"
                and record.status == "SUCCESS"
                and record.username
            ):
                continue

            ts = parse_ts(record.timestamp)
            if ts is None:
                continue
            hour = ts.astimezone(timezone.utc).hour
            if not self._is_off_hours(hour):
                continue

            seen = ts_to_str(ts)
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
                    f"Successful login for '{record.username}' at {hour:02d}:00 UTC, "
                    f"outside the configured {self.start_hour:02d}:00-{self.end_hour:02d}:00 window."
                ),
                matched_line_numbers=[record.line_number],
                mitre_technique=self.mitre_technique,
                confidence=self.confidence,
                entity_type=self.entity_type,
                entity_id=record.username,
            ))
        return alerts
