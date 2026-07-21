from __future__ import annotations

from collections import defaultdict, deque

from app.detection._ts import parse_ts, ts_to_str
from app.detection.models import Alert, LogRecord
from app.detection.rules.base import BaseRule


class CredentialStuffingRule(BaseRule):
    """Fires when a burst of failed logins from an IP is immediately followed by
    a successful login from that same IP — the brute-force likely succeeded.

    BruteForceLoginRule already flags the failure burst on its own, but stops
    tracking once it fires. This rule closes the gap: an attacker who guesses
    correctly right after a burst represents a probable account takeover.
    """

    def __init__(
        self,
        fail_threshold: int = 5,
        window_seconds: int = 60,
        success_window_seconds: int = 120,
    ):
        self.fail_threshold = fail_threshold
        self.window_seconds = window_seconds
        self.success_window_seconds = success_window_seconds

    def analyze(self, records: list[LogRecord]) -> list[Alert]:
        candidates = [
            r for r in records
            if r.event_type == "login_attempt"
            and r.ip_address
            and r.status in ("FAILED", "SUCCESS")
        ]

        by_ip: dict[str, list[LogRecord]] = defaultdict(list)
        for r in candidates:
            by_ip[r.ip_address].append(r)

        alerts: list[Alert] = []
        for ip, recs in by_ip.items():
            timed = [
                (r, ts) for r, ts in sorted(
                    [(r, parse_ts(r.timestamp)) for r in recs],
                    key=lambda x: (x[1] is None, x[1]),
                )
                if ts is not None
            ]

            fail_window: deque = deque()
            burst_records: list[tuple[LogRecord, object]] = []
            burst_end_ts = None

            for rec, ts in timed:
                if rec.status == "FAILED":
                    fail_window.append((rec, ts))
                    while fail_window and (ts - fail_window[0][1]).total_seconds() > self.window_seconds:
                        fail_window.popleft()
                    if len(fail_window) >= self.fail_threshold:
                        burst_records = list(fail_window)
                        burst_end_ts = ts
                    continue

                # rec.status == "SUCCESS"
                if burst_end_ts is not None and (ts - burst_end_ts).total_seconds() <= self.success_window_seconds:
                    alerts.append(Alert(
                        rule="credential_stuffing_success",
                        severity="HIGH",
                        source_ip=ip,
                        username=rec.username,
                        count=len(burst_records) + 1,
                        time_window_seconds=self.window_seconds + self.success_window_seconds,
                        first_seen=ts_to_str(burst_records[0][1]),
                        last_seen=ts_to_str(ts),
                        description=(
                            f"Possible account takeover from {ip}: "
                            f"{len(burst_records)} failed logins followed by a successful login "
                            f"within {self.success_window_seconds}s of the failure burst."
                        ),
                        matched_line_numbers=[r.line_number for r, _ in burst_records] + [rec.line_number],
                    ))

                # A success resolves the burst either way — start clean.
                fail_window.clear()
                burst_records = []
                burst_end_ts = None

        return alerts
