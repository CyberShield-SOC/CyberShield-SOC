from __future__ import annotations

from collections import defaultdict, deque

from app.detection._ts import parse_ts, ts_to_str
from app.detection.models import Alert, LogRecord
from app.detection.rules.base import BaseRule


class SudoFailureRule(BaseRule):
    """Fires when the same user (or IP) has >= threshold sudo failures within window_seconds."""

    def __init__(self, threshold: int = 3, window_seconds: int = 300):
        self.threshold = threshold
        self.window_seconds = window_seconds

    def analyze(self, records: list[LogRecord]) -> list[Alert]:
        candidates = [
            r for r in records
            if r.event_type == "privilege_escalation"
            and r.status == "FAILED"
        ]

        # Group by username first; fall back to IP for anonymous sudo attempts
        by_subject: dict[str, list[LogRecord]] = defaultdict(list)
        for r in candidates:
            key = r.username or r.ip_address
            if key:
                by_subject[key].append(r)

        alerts: list[Alert] = []
        for subject, recs in by_subject.items():
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

                if len(window) >= self.threshold:
                    matched = list(window)
                    sample = matched[0][0]
                    alerts.append(Alert(
                        rule="sudo_failure",
                        severity="MEDIUM",
                        source_ip=sample.ip_address,
                        username=sample.username,
                        count=len(matched),
                        time_window_seconds=self.window_seconds,
                        first_seen=ts_to_str(matched[0][1]),
                        last_seen=ts_to_str(matched[-1][1]),
                        description=(
                            f"Repeated sudo failures for '{subject}': "
                            f"{len(matched)} failures within {self.window_seconds}s. "
                            "Possible privilege escalation attempt."
                        ),
                        matched_line_numbers=[r.line_number for r, _ in matched],
                    ))
                    window.clear()

        return alerts
