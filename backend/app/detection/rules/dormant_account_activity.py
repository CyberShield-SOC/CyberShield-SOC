from __future__ import annotations

from app.detection._ts import parse_ts, ts_to_str
from app.detection.models import Alert, LogRecord
from app.detection.rules.base import BaseRule
from app.repositories.baseline_repository import get_baseline, set_baseline

BASELINE_KEY = "last_login_at"


class DormantAccountActivityRule(BaseRule):
    """Fires when an account authenticates successfully after being idle for
    at least `threshold` days, using a persistent per-account "last login"
    baseline carried across uploads (see app/repositories/baseline_repository.py).

    Requires a database session — DetectionEngine.run passes one when
    available. With none (e.g. a pure in-memory analyze() call), this rule
    produces no alerts rather than guessing at history it doesn't have.
    """

    name = "dormant_account_activity"
    description = "An account authenticated after being idle for an extended period."
    severity = "MEDIUM"
    mitre_technique = "T1078"
    entity_type = "account"
    confidence = 55

    def __init__(self, cooldown_seconds: int = 0, threshold: int = 30):
        self.cooldown_seconds = cooldown_seconds
        # `threshold` is the idle period in days, reusing the generic config
        # field so it's tunable through DETECTION_RULE_CONFIG / PATCH.
        self.threshold = threshold

    def analyze(self, records: list[LogRecord], db=None) -> list[Alert]:
        if db is None:
            return []

        candidates = sorted(
            (
                (r, ts)
                for r in records
                if r.event_type == "login_attempt" and r.status == "SUCCESS" and r.username
                for ts in [parse_ts(r.timestamp)]
                if ts is not None
            ),
            key=lambda item: item[1],
        )

        alerts: list[Alert] = []
        last_seen_in_batch: dict[str, object] = {}

        for record, ts in candidates:
            username = record.username
            reference = last_seen_in_batch.get(username)
            if reference is None:
                stored = get_baseline(
                    db, entity_type="account", entity_id=username, baseline_key=BASELINE_KEY
                )
                if stored and stored.get("last_login_at"):
                    reference = parse_ts(stored["last_login_at"])

            if reference is not None:
                idle_days = (ts - reference).total_seconds() / 86400
                if idle_days >= self.threshold:
                    seen = ts_to_str(ts)
                    alerts.append(Alert(
                        rule=self.name,
                        severity=self.severity,
                        source_ip=record.ip_address,
                        username=username,
                        hostname=record.hostname,
                        count=1,
                        time_window_seconds=self.cooldown_seconds,
                        first_seen=seen,
                        last_seen=seen,
                        description=(
                            f"Account '{username}' authenticated after "
                            f"{idle_days:.0f} days of inactivity (threshold {self.threshold})."
                        ),
                        matched_line_numbers=[record.line_number],
                        mitre_technique=self.mitre_technique,
                        confidence=self.confidence,
                        entity_type=self.entity_type,
                        entity_id=username,
                    ))

            last_seen_in_batch[username] = ts

        for username, ts in last_seen_in_batch.items():
            set_baseline(
                db,
                entity_type="account",
                entity_id=username,
                baseline_key=BASELINE_KEY,
                value={"last_login_at": ts_to_str(ts)},
            )

        return alerts
