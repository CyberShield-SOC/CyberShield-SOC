from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone

from app.detection._ts import parse_ts, ts_to_str
from app.detection.geoip import is_public_ip
from app.detection.models import Alert, LogRecord
from app.detection.rules._host_alerts import endpoint_id
from app.detection.rules.base import BaseRule
from app.ml.features_egress_volume import ENTITY_TYPE, FEATURE_NAMES, FEATURE_SET, egress_volume_features
from app.ml.pipeline import load_active, record_and_score

_BUCKET_SECONDS = 3600  # one hour — same granularity as EgressVolumeAnomalyRule


def _bucket_start(ts: datetime, window_seconds: int) -> int:
    epoch = int(ts.astimezone(timezone.utc).timestamp())
    return epoch - epoch % window_seconds


class BehavioralAnomalyEgressRule(BaseRule):
    """
    Learned, joint anomaly score over one host's hourly egress bucket —
    pilot #2 from docs/ml/isolation_forest_feasibility.md, explicitly the
    doc's top pick since egress_volume_anomaly already had the closest
    thing to feature history (a single-dimension EWMA baseline).

    Where egress_volume_anomaly compares bytes_out alone against that one
    host's own running mean, this scores bytes, connection count, distinct
    destinations, and time of day *together* against the trained
    population — catching e.g. a moderate volume increase at an unusual
    hour to an unusually large number of destinations, a combination that
    might individually stay under egress_volume_anomaly's own thresholds.

    Same two-gate shadow mode as behavioral_anomaly_login: no active model
    means pure snapshot collection; once one exists, `params.shadow_mode`
    (default True) still holds back real alerts until an admin reviews
    GET /ml/scores and deliberately turns it off for this rule.

    Needs the same byte-count columns egress_volume_anomaly needs: CSV/JSON
    flow or proxy exports. Firewall packet logs don't carry them.
    """

    name = "behavioral_anomaly_egress"
    description = "A host's hourly egress pattern scored as unusual against a trained population model."
    severity = "LOW"
    mitre_technique = "T1041"
    entity_type = "host"
    confidence = 40
    DEFAULT_PARAMS = {"score_threshold": -0.02, "shadow_mode": True}

    def __init__(self, cooldown_seconds: int = 3600, params: dict | None = None):
        self.cooldown_seconds = cooldown_seconds
        self.params = self.merge_params(params)

    def analyze(self, records: list[LogRecord], db=None) -> list[Alert]:
        if db is None:
            return []

        buckets: dict[tuple[str, int], dict] = defaultdict(
            lambda: {"bytes": 0, "connections": 0, "destinations": set(), "records": []}
        )
        for record in records:
            if not record.bytes_out:
                continue
            if record.dest_ip and not is_public_ip(record.dest_ip):
                continue
            internal_ip = record.ip_address if not is_public_ip(record.ip_address) else None
            host = endpoint_id(record, internal_ip)
            if not host:
                continue
            ts = parse_ts(record.timestamp)
            if ts is None:
                continue
            bucket = buckets[(host, _bucket_start(ts, _BUCKET_SECONDS))]
            bucket["bytes"] += record.bytes_out
            bucket["connections"] += 1
            if record.dest_ip:
                bucket["destinations"].add(record.dest_ip)
            bucket["records"].append(record)

        if not buckets:
            return []

        model_row, estimator = load_active(
            db, feature_set=FEATURE_SET, entity_type=ENTITY_TYPE, feature_names=FEATURE_NAMES
        )
        threshold = float(self.params["score_threshold"])
        shadow_mode = bool(self.params["shadow_mode"])

        alerts: list[Alert] = []
        for (host, bucket_start), data in buckets.items():
            ts = datetime.fromtimestamp(bucket_start, tz=timezone.utc)
            features = egress_volume_features(
                ts, bytes_out=data["bytes"], connection_count=data["connections"],
                distinct_destinations=len(data["destinations"]),
            )
            _snapshot, scored = record_and_score(
                db, feature_set=FEATURE_SET, entity_type=ENTITY_TYPE, entity_id=host,
                captured_at=ts, features=features, model_row=model_row, estimator=estimator,
            )

            if scored is not None and not shadow_mode and scored.score < threshold:
                alerts.append(self._alert(host, ts, data, model_row, scored, threshold))

        return alerts

    def _alert(self, host: str, ts: datetime, data: dict, model_row, scored, threshold: float) -> Alert:
        seen = ts_to_str(ts)
        top = scored.top_deviations()
        reason = ", ".join(f"{d.feature} {d.z_score:+.1f} SD" for d in top)
        sample = data["records"][0]
        return Alert(
            rule=self.name,
            severity=self.severity,
            source_ip=sample.ip_address,
            hostname=host,
            count=data["connections"],
            time_window_seconds=_BUCKET_SECONDS,
            first_seen=seen,
            last_seen=seen,
            description=(
                f"Egress pattern for {host} scored as behaviorally unusual "
                f"(score {scored.score:.3f}, threshold {threshold:.3f}): {reason}."
            ),
            matched_line_numbers=[r.line_number for r in data["records"]],
            mitre_technique=self.mitre_technique,
            confidence=self.confidence,
            entity_type=self.entity_type,
            entity_id=host,
            evidence={
                "score": round(scored.score, 4),
                "threshold": threshold,
                "bytes_out": data["bytes"],
                "connection_count": data["connections"],
                "distinct_destinations": len(data["destinations"]),
                "feature_deviations": [
                    {"feature": d.feature, "value": round(d.value, 4), "z_score": round(d.z_score, 2)}
                    for d in top
                ],
                "model_version": model_row.version,
                "model_sample_count": model_row.sample_count,
                "model_trained_at": model_row.trained_at.isoformat() if model_row.trained_at else None,
            },
        )
