from collections import defaultdict, deque

from app.detection._ts import parse_ts, ts_to_str
from app.detection.models import Alert, LogRecord
from app.detection.rules.base import BaseRule


class MultiIPLoginRule(BaseRule):
    """Flag a successful account used from several IPs in a short interval."""

    name = "multi_ip_successful_login"
    description = "One account has successful logins from multiple source IPs in a short window."
    severity = "MEDIUM"

    def __init__(self, threshold: int = 3, window_seconds: int = 300):
        self.threshold = threshold
        self.window_seconds = window_seconds

    def analyze(self, records: list[LogRecord]) -> list[Alert]:
        by_user = defaultdict(list)
        for record in records:
            if record.event_type == "login_attempt" and record.status == "SUCCESS" and record.username and record.ip_address:
                ts = parse_ts(record.timestamp)
                if ts is not None:
                    by_user[record.username].append((record, ts))

        alerts = []
        for username, events in by_user.items():
            window = deque()
            for record, ts in sorted(events, key=lambda event: event[1]):
                window.append((record, ts))
                while (ts - window[0][1]).total_seconds() > self.window_seconds:
                    window.popleft()
                if len({entry.ip_address for entry, _ in window}) >= self.threshold:
                    matched = list(window)
                    alerts.append(Alert(
                        rule=self.name, severity=self.severity, source_ip=record.ip_address,
                        username=username, count=len(matched), time_window_seconds=self.window_seconds,
                        first_seen=ts_to_str(matched[0][1]), last_seen=ts_to_str(ts),
                        description=f"Account {username} logged in from {self.threshold} or more IPs within {self.window_seconds}s.",
                        matched_line_numbers=[entry.line_number for entry, _ in matched],
                    ))
                    window.clear()
        return alerts
