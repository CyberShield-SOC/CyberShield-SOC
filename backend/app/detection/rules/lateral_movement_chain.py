from __future__ import annotations

from collections import defaultdict, deque

from app.detection._ts import parse_ts, ts_to_str
from app.detection.models import Alert, LogRecord
from app.detection.rules.base import BaseRule
from app.repositories.baseline_repository import get_baseline, set_baseline

BASELINE_KEY = "recent_hosts"


class LateralMovementChainRule(BaseRule):
    """Fires when the same account authenticates successfully across
    >= threshold distinct hosts within window_seconds.

    Uses syslog's `hostname` field (the host being logged into) as the host
    entity — syslog sources only. Chains a persistent per-account
    "recently used hosts" baseline across uploads (see
    app/repositories/baseline_repository.py) so this also catches a chain
    that spans separate uploads, not just multi-host logs in one upload; a
    missing database session (e.g. in-memory analyze() calls in tests) just
    means only the current batch's records are considered.
    """

    name = "lateral_movement_chain"
    description = "One account authenticated across several hosts in quick succession."
    severity = "HIGH"
    mitre_technique = "T1021.004"
    entity_type = "account"
    confidence = 65

    def __init__(self, threshold: int = 3, window_seconds: int = 600, cooldown_seconds: int = 0):
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.cooldown_seconds = cooldown_seconds

    def analyze(self, records: list[LogRecord], db=None) -> list[Alert]:
        candidates = [
            r for r in records
            if r.event_type == "login_attempt"
            and r.status == "SUCCESS"
            and r.username
            and r.hostname
        ]

        by_user: dict[str, list[LogRecord]] = defaultdict(list)
        for r in candidates:
            by_user[r.username].append(r)

        alerts: list[Alert] = []
        for username, recs in by_user.items():
            batch_events = sorted(
                (
                    (r, ts)
                    for r in recs
                    for ts in [parse_ts(r.timestamp)]
                    if ts is not None
                ),
                key=lambda item: item[1],
            )

            history: list[tuple[None, object, str]] = []
            if db is not None:
                stored = get_baseline(
                    db, entity_type="account", entity_id=username, baseline_key=BASELINE_KEY
                )
                for item in (stored or {}).get("events", []):
                    ts = parse_ts(item.get("ts"))
                    host = item.get("host")
                    if ts is not None and host:
                        history.append((None, ts, host))

            combined = sorted(
                [(r, ts, r.hostname, True) for r, ts in batch_events]
                + [(rec, ts, host, False) for rec, ts, host in history],
                key=lambda item: item[1],
            )

            window: deque = deque()
            for rec, ts, host, is_new in combined:
                window.append((rec, ts, host, is_new))
                while window and (ts - window[0][1]).total_seconds() > self.window_seconds:
                    window.popleft()

                distinct_hosts = {h for _, _, h, _ in window}
                if len(distinct_hosts) >= self.threshold and is_new:
                    matched = list(window)
                    alerts.append(Alert(
                        rule=self.name,
                        severity=self.severity,
                        username=username,
                        hostname=host,
                        count=len(matched),
                        time_window_seconds=self.window_seconds,
                        first_seen=ts_to_str(matched[0][1]),
                        last_seen=ts_to_str(ts),
                        description=(
                            f"Account '{username}' authenticated across "
                            f"{len(distinct_hosts)} hosts within {self.window_seconds}s: "
                            f"{', '.join(sorted(distinct_hosts))}."
                        ),
                        matched_line_numbers=[
                            item[0].line_number for item in matched if item[0] is not None
                        ],
                        mitre_technique=self.mitre_technique,
                        confidence=self.confidence,
                        entity_type=self.entity_type,
                        entity_id=username,
                    ))
                    window.clear()

            if db is not None and combined:
                newest_ts = combined[-1][1]
                recent = [
                    {"host": host, "ts": ts_to_str(ts)}
                    for _, ts, host, _ in combined
                    if (newest_ts - ts).total_seconds() <= self.window_seconds
                ]
                set_baseline(
                    db,
                    entity_type="account",
                    entity_id=username,
                    baseline_key=BASELINE_KEY,
                    value={"events": recent},
                )

        return alerts
