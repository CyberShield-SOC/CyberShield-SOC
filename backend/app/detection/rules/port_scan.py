from __future__ import annotations

from collections import defaultdict, deque

from app.detection._ts import parse_ts, ts_to_str
from app.detection.models import Alert, LogRecord
from app.detection.rules.base import BaseRule


class PortScanRule(BaseRule):
    """Fires when one source IP generates >= threshold port-scan events within window_seconds."""

    def __init__(self, threshold: int = 10, window_seconds: int = 60):
        self.threshold = threshold
        self.window_seconds = window_seconds

    def analyze(self, records: list[LogRecord]) -> list[Alert]:
        candidates = [
            r for r in records
            if r.event_type == "port_scan"
            and r.ip_address
        ]

        by_ip: dict[str, list[LogRecord]] = defaultdict(list)
        for r in candidates:
            by_ip[r.ip_address].append(r)

        alerts: list[Alert] = []
        for ip, recs in by_ip.items():
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
                    alerts.append(Alert(
                        rule="port_scan",
                        severity="MEDIUM",
                        source_ip=ip,
                        username=matched[0][0].username,
                        count=len(matched),
                        time_window_seconds=self.window_seconds,
                        first_seen=ts_to_str(matched[0][1]),
                        last_seen=ts_to_str(matched[-1][1]),
                        description=(
                            f"Port scan detected from {ip}: "
                            f"{len(matched)} scan events within {self.window_seconds}s."
                        ),
                        matched_line_numbers=[r.line_number for r, _ in matched],
                    ))
                    window.clear()

        return alerts
