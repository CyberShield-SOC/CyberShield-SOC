from collections import defaultdict, deque

from app.detection._ts import parse_ts, ts_to_str
from app.detection.models import Alert, LogRecord
from app.detection.rules.base import BaseRule


class SudoAfterLoginRule(BaseRule):
    """Flag rapid successful privilege escalation following a successful login."""

    name = "sudo_after_login"
    description = "A successful login is followed quickly by successful privilege escalation for the same account."
    severity = "MEDIUM"

    def __init__(self, window_seconds: int = 120):
        self.window_seconds = window_seconds

    def analyze(self, records: list[LogRecord]) -> list[Alert]:
        by_user = defaultdict(list)
        for record in records:
            if record.username and record.status == "SUCCESS" and record.event_type in {"login_attempt", "privilege_escalation"}:
                ts = parse_ts(record.timestamp)
                if ts is not None:
                    by_user[record.username].append((record, ts))

        alerts = []
        for username, events in by_user.items():
            logins = deque()
            for record, ts in sorted(events, key=lambda event: event[1]):
                while logins and (ts - logins[0][1]).total_seconds() > self.window_seconds:
                    logins.popleft()
                if record.event_type == "login_attempt":
                    logins.append((record, ts))
                elif logins:
                    login, login_ts = logins[-1]
                    if login.ip_address and record.ip_address and login.ip_address != record.ip_address:
                        continue
                    alerts.append(Alert(
                        rule=self.name, severity=self.severity,
                        source_ip=record.ip_address or login.ip_address, username=username,
                        count=2, time_window_seconds=self.window_seconds,
                        first_seen=ts_to_str(login_ts), last_seen=ts_to_str(ts),
                        description=f"Account {username} escalated privileges within {self.window_seconds}s of login.",
                        matched_line_numbers=[login.line_number, record.line_number],
                    ))
                    logins.clear()
        return alerts
