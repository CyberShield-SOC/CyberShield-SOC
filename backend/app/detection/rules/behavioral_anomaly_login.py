from __future__ import annotations

from app.detection._ts import parse_ts, ts_to_str
from app.detection.models import Alert, LogRecord
from app.detection.rules.base import BaseRule
from app.ml.features import ENTITY_TYPE, FEATURE_NAMES, FEATURE_SET, login_behavior_features
from app.ml.pipeline import load_active, record_and_score
from app.repositories.baseline_repository import get_baseline, set_baseline

# Own baseline key, deliberately not shared with first_seen_geo_asn.py even
# though both track "known countries per account": engine.run() executes
# rules in list order within one shared DB session, and this rule's read
# must not depend on whether that other rule has already flushed an update
# for the same batch. A private key makes this rule's output independent of
# registration order.
_KNOWN_COUNTRIES_KEY = "login_behavior_known_countries"
_MAX_REMEMBERED = 100


class BehavioralAnomalyLoginRule(BaseRule):
    """
    Learned, joint anomaly score over a login's time-of-day, day-of-week,
    and whether its country is new for the account — pilot #1 from
    docs/ml/isolation_forest_feasibility.md.

    Every successful login always gets a feature snapshot persisted
    (app.ml.features.login_behavior_features), building the training
    population app/ml/train_login_behavior.py needs. Scoring only starts
    once an admin has actually run that training script — no active model
    (app.repositories.ml_repository.get_active_model) is this project's
    first stand-in for shadow mode. Once a model exists, `params.shadow_mode`
    (default True) is the second one: scores get computed and stored on
    every snapshot either way (reviewable via GET /ml/scores), but no Alert
    is raised until an admin deliberately sets shadow_mode to false for this
    rule — the two-step rollout the feasibility doc's §5.5 asked for.

    Unlike off_hours_login (fixed hours) or first_seen_geo_asn (either
    known or not), this can flag a combination — an in-hours login from a
    borderline-unusual time paired with a new country — that neither
    threshold alone would catch. Severity stays LOW and confidence stays
    low by design: this is advisory, not a verdict.
    """

    name = "behavioral_anomaly_login"
    description = "A login's time/geo combination scored as unusual against a trained population model."
    severity = "LOW"
    mitre_technique = "T1078"
    entity_type = "account"
    confidence = 45
    DEFAULT_PARAMS = {"score_threshold": -0.02, "shadow_mode": True}

    def __init__(self, cooldown_seconds: int = 3600, params: dict | None = None):
        self.cooldown_seconds = cooldown_seconds
        self.params = self.merge_params(params)

    def analyze(self, records: list[LogRecord], db=None) -> list[Alert]:
        if db is None:
            return []

        candidates = sorted(
            (
                (ts, record)
                for record in records
                if record.event_type == "login_attempt" and record.status == "SUCCESS" and record.username
                for ts in [parse_ts(record.timestamp)]
                if ts is not None
            ),
            key=lambda item: item[0],
        )
        if not candidates:
            return []

        model_row, estimator = load_active(
            db, feature_set=FEATURE_SET, entity_type=ENTITY_TYPE, feature_names=FEATURE_NAMES
        )
        threshold = float(self.params["score_threshold"])
        shadow_mode = bool(self.params["shadow_mode"])

        known_countries: dict[str, list[str]] = {}
        alerts: list[Alert] = []

        for ts, record in candidates:
            user = record.username
            if user not in known_countries:
                stored = get_baseline(
                    db, entity_type="account", entity_id=user, baseline_key=_KNOWN_COUNTRIES_KEY
                )
                known_countries[user] = list((stored or {}).get("countries") or [])
            countries = known_countries[user]
            is_new_geo = bool(record.country) and record.country not in countries

            features = login_behavior_features(ts, is_new_geo=is_new_geo)
            _snapshot, scored = record_and_score(
                db, feature_set=FEATURE_SET, entity_type=ENTITY_TYPE, entity_id=user,
                captured_at=ts, features=features, model_row=model_row, estimator=estimator,
            )

            if scored is not None and not shadow_mode and scored.score < threshold:
                alerts.append(self._alert(record, ts, user, model_row, scored, threshold))

            if record.country and record.country not in countries:
                known_countries[user] = (countries + [record.country])[-_MAX_REMEMBERED:]

        for user, countries in known_countries.items():
            set_baseline(
                db, entity_type="account", entity_id=user,
                baseline_key=_KNOWN_COUNTRIES_KEY, value={"countries": countries},
            )

        return alerts

    def _alert(self, record: LogRecord, ts, user: str, model_row, scored, threshold: float) -> Alert:
        seen = ts_to_str(ts)
        top = scored.top_deviations()
        # Plain ASCII deliberately (no "σ") — this string travels through
        # Windows console logging, CSV export, and non-UTF8 terminals; a
        # unicode symbol here has broken at least one of those in testing.
        reason = ", ".join(f"{d.feature} {d.z_score:+.1f} SD" for d in top)
        return Alert(
            rule=self.name,
            severity=self.severity,
            source_ip=record.ip_address,
            username=user,
            hostname=record.hostname,
            count=1,
            time_window_seconds=self.cooldown_seconds,
            first_seen=seen,
            last_seen=seen,
            description=(
                f"Login for '{user}' scored as behaviorally unusual "
                f"(score {scored.score:.3f}, threshold {threshold:.3f}): {reason}."
            ),
            matched_line_numbers=[record.line_number],
            mitre_technique=self.mitre_technique,
            confidence=self.confidence,
            entity_type=self.entity_type,
            entity_id=user,
            evidence={
                "score": round(scored.score, 4),
                "threshold": threshold,
                "feature_deviations": [
                    {"feature": d.feature, "value": round(d.value, 4), "z_score": round(d.z_score, 2)}
                    for d in top
                ],
                "model_version": model_row.version,
                "model_sample_count": model_row.sample_count,
                "model_trained_at": model_row.trained_at.isoformat() if model_row.trained_at else None,
            },
        )
