from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone

from app.detection._ts import parse_ts, ts_to_str
from app.detection.models import Alert, LogRecord
from app.detection.rules.base import BaseRule
from app.ml.features_threat_log import (
    ENTITY_TYPE,
    FEATURE_NAMES,
    FEATURE_SET,
    empty_history,
    threat_log_features,
    update_history,
)
from app.ml.pipeline import load_active, record_and_score
from app.repositories.baseline_repository import get_baseline, set_baseline

_BUCKET_SECONDS = 3600  # one hour — same granularity as behavioral_anomaly_egress

_DENIED_STATUSES = frozenset({"FAILED", "DENIED", "BLOCKED", "DROP", "DROPPED", "REJECTED"})

BASELINE_KEY = "traffic_history"


def _bucket_start(ts: datetime, window_seconds: int) -> int:
    epoch = int(ts.astimezone(timezone.utc).timestamp())
    return epoch - epoch % window_seconds


class BehavioralAnomalyThreatLogRule(BaseRule):
    """
    Learned, joint anomaly score over one source IP's hourly traffic bucket —
    pilot #3, following the offline evaluation in ml_experiments/ that found
    cybersecurity_threat_detection_logs.csv was the only one of 5 candidate
    datasets whose anomaly label actually correlated with observable traffic
    features (ROC-AUC 0.72 for a one-hot/per-row model; see
    ml_experiments/reports/threat_detection_logs.txt). No time-of-day feature
    here — every row in that CSV carried hour=0, so cyclic hour/day-of-week
    features were dead weight there; see
    ml_experiments/reports/threat_detection_logs_production_features.txt.

    Where host_sweep/port_scan use fixed thresholds on one dimension at a
    time, this scores volume, destination/port fan-out, deny rate, and
    rarity/novelty of this bucket's destinations/ports/protocols against
    this source IP's own running history (the same "have we seen this
    before" judgment first_seen_geo_asn's `is_new_geo` uses, generalized to
    three dimensions and a continuous score instead of one flag) — the same
    joint-anomaly idea as behavioral_anomaly_login/_egress, minus the time
    dimension those two rely on. See features_threat_log.py for the full
    feature list and the rationale for each one.

    The running history is kept per source IP in entity_baselines (same
    mechanism and same caveats as first_seen_geo_asn's `known_geo`): capped
    to the most-frequent HISTORY_CAP values per dimension, updated only
    *after* a bucket has been scored against the pre-update baseline, never
    before — a bucket must never be able to make itself look less
    surprising by being included in its own history.

    Same two-gate shadow mode: no active model means pure snapshot
    collection; once one exists, `params.shadow_mode` (default True) still
    holds back real alerts until an admin reviews GET /ml/scores and
    deliberately turns it off for this rule.

    Needs connection events carrying source IP and destination IP/port:
    firewall kernel logs or CSV/JSON flow/proxy exports — the same sources
    host_sweep and port_scan already require.
    """

    name = "behavioral_anomaly_threat_log"
    description = "A source IP's hourly traffic pattern scored as unusual against a trained population model."
    severity = "LOW"
    mitre_technique = "T1046"
    entity_type = "source_ip"
    confidence = 40
    # -0.12 is provisional: derived from synthetic validation only (see
    # ml_experiments/README.md and ml_experiments/reports/
    # threat_log_false_positive_powered.txt) -- a 100-normal-IP x 10-seed x
    # 4-novelty-level population gave ~0.8% false positives per bucket at
    # this threshold with 100% detection of both loud and subtle injected
    # attacks. It has never seen real traffic. Re-derive it from GET
    # /ml/scores once real shadow-mode data accumulates, rather than
    # trusting this number indefinitely.
    DEFAULT_PARAMS = {"score_threshold": -0.12, "shadow_mode": True}

    def __init__(self, cooldown_seconds: int = 3600, params: dict | None = None):
        self.cooldown_seconds = cooldown_seconds
        self.params = self.merge_params(params)

    def analyze(self, records: list[LogRecord], db=None) -> list[Alert]:
        if db is None:
            return []

        buckets: dict[tuple[str, int], dict] = defaultdict(
            lambda: {
                "bytes": 0, "connections": 0, "denied": 0,
                "dest_counts": Counter(), "port_counts": Counter(), "protocol_counts": Counter(),
                "records": [],
            }
        )
        for record in records:
            if not (record.ip_address and record.dest_ip):
                continue
            ts = parse_ts(record.timestamp)
            if ts is None:
                continue
            bucket = buckets[(record.ip_address, _bucket_start(ts, _BUCKET_SECONDS))]
            bucket["bytes"] += (record.bytes_out or 0) + (record.bytes_in or 0)
            bucket["connections"] += 1
            bucket["dest_counts"][record.dest_ip] += 1
            if record.port:
                bucket["port_counts"][str(record.port)] += 1
            if record.protocol:
                bucket["protocol_counts"][record.protocol] += 1
            if (record.status or "").upper() in _DENIED_STATUSES:
                bucket["denied"] += 1
            bucket["records"].append(record)

        if not buckets:
            return []

        model_row, estimator = load_active(
            db, feature_set=FEATURE_SET, entity_type=ENTITY_TYPE, feature_names=FEATURE_NAMES
        )
        threshold = float(self.params["score_threshold"])
        shadow_mode = bool(self.params["shadow_mode"])

        # Grouped by source IP, then walked in chronological bucket order per
        # source, so each bucket is scored against this IP's history strictly
        # before that bucket happened — never against a baseline that already
        # includes it (see update_history's docstring).
        by_source: dict[str, list[int]] = defaultdict(list)
        for source, bucket_start in buckets:
            by_source[source].append(bucket_start)

        alerts: list[Alert] = []
        for source, bucket_starts in by_source.items():
            history = get_baseline(db, entity_type=ENTITY_TYPE, entity_id=source, baseline_key=BASELINE_KEY)
            if history is None:
                history = empty_history()

            for bucket_start in sorted(bucket_starts):
                data = buckets[(source, bucket_start)]
                ts = datetime.fromtimestamp(bucket_start, tz=timezone.utc)
                features = threat_log_features(
                    bytes_total=data["bytes"], connection_count=data["connections"], denied_count=data["denied"],
                    dest_counts=data["dest_counts"], port_counts=data["port_counts"],
                    protocol_counts=data["protocol_counts"], history=history,
                )
                _snapshot, scored = record_and_score(
                    db, feature_set=FEATURE_SET, entity_type=ENTITY_TYPE, entity_id=source,
                    captured_at=ts, features=features, model_row=model_row, estimator=estimator,
                )

                if scored is not None and not shadow_mode and scored.score < threshold:
                    alerts.append(self._alert(source, ts, data, model_row, scored, threshold))

                history = update_history(
                    history, dest_counts=data["dest_counts"], port_counts=data["port_counts"],
                    protocol_counts=data["protocol_counts"], connection_count=data["connections"],
                )

            set_baseline(db, entity_type=ENTITY_TYPE, entity_id=source, baseline_key=BASELINE_KEY, value=history)

        return alerts

    def _alert(self, source: str, ts: datetime, data: dict, model_row, scored, threshold: float) -> Alert:
        seen = ts_to_str(ts)
        top = scored.top_deviations()
        reason = ", ".join(f"{d.feature} {d.z_score:+.1f} SD" for d in top)
        return Alert(
            rule=self.name,
            severity=self.severity,
            source_ip=source,
            count=data["connections"],
            time_window_seconds=_BUCKET_SECONDS,
            first_seen=seen,
            last_seen=seen,
            description=(
                f"Traffic pattern for {source} scored as behaviorally unusual "
                f"(score {scored.score:.3f}, threshold {threshold:.3f}): {reason}."
            ),
            matched_line_numbers=[r.line_number for r in data["records"]],
            mitre_technique=self.mitre_technique,
            confidence=self.confidence,
            entity_type=self.entity_type,
            entity_id=source,
            evidence={
                "score": round(scored.score, 4),
                "threshold": threshold,
                "bytes_total": data["bytes"],
                "connection_count": data["connections"],
                "distinct_destinations": len(data["dest_counts"]),
                "distinct_ports": len(data["port_counts"]),
                "denied_count": data["denied"],
                "feature_deviations": [
                    {"feature": d.feature, "value": round(d.value, 4), "z_score": round(d.z_score, 2)}
                    for d in top
                ],
                "model_version": model_row.version,
                "model_sample_count": model_row.sample_count,
                "model_trained_at": model_row.trained_at.isoformat() if model_row.trained_at else None,
            },
        )
