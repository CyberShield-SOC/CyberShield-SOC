from __future__ import annotations

from collections import defaultdict, deque

from app.detection._ts import parse_ts, ts_to_str
from app.detection.models import Alert, LogRecord
from app.detection.rules.base import BaseRule


class PasswordSprayingRule(BaseRule):
    """Fires when one username receives failed logins from >= threshold distinct source IPs within window_seconds.

    This is the inverse grouping of BruteForceLoginRule: instead of one IP
    hammering one account, many IPs each try the same account a handful of
    times to stay under per-IP thresholds.
    """

    def __init__(self, threshold: int = 5, window_seconds: int = 600):
        self.threshold = threshold
        self.window_seconds = window_seconds

    def analyze(self, records: list[LogRecord]) -> list[Alert]:
        candidates = [
            r for r in records
            if r.status == "FAILED"
            and r.event_type == "login_attempt"
            and r.ip_address
            and r.username
        ]

        by_username: dict[str, list[LogRecord]] = defaultdict(list)
        for r in candidates:
            by_username[r.username].append(r)

        alerts: list[Alert] = []
        for username, recs in by_username.items():
            timed = sorted(
                [(r, parse_ts(r.timestamp)) for r in recs],
                key=lambda x: (x[1] is None, x[1]),
            )
            window: deque = deque()

            for rec, ts in timed:
                if ts is None:
                    continue
                window.append((rec, ts))
                while window and (ts - window[0][1]).total_seconds() > self.window_seconds:
                    window.popleft()

                distinct_ips = {r.ip_address for r, _ in window}
                if len(distinct_ips) >= self.threshold:
                    matched = list(window)
                    alerts.append(Alert(
                        rule="password_spraying",
                        severity="HIGH",
                        source_ip=matched[-1][0].ip_address,
                        username=username,
                        count=len(distinct_ips),
                        time_window_seconds=self.window_seconds,
                        first_seen=ts_to_str(matched[0][1]),
                        last_seen=ts_to_str(matched[-1][1]),
                        description=(
                            f"Password spraying detected against '{username}': "
                            f"{len(distinct_ips)} distinct source IPs failed to authenticate "
                            f"within {self.window_seconds}s."
                        ),
                        matched_line_numbers=[r.line_number for r, _ in matched],
                    ))
                    window.clear()

        return alerts
