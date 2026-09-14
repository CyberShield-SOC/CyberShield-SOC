from __future__ import annotations

import math
from collections import defaultdict
from datetime import datetime, timezone

from app.detection._ts import parse_ts, ts_to_str
from app.detection.geoip import is_public_ip
from app.detection.models import Alert, LogRecord
from app.detection.rules._host_alerts import endpoint_id
from app.detection.rules.base import BaseRule
from app.repositories.baseline_repository import get_baseline, set_baseline

BASELINE_KEY = "egress_bytes_per_window"
_EWMA_ALPHA = 0.2


class EgressVolumeAnomalyRule(BaseRule):
    """Fires when a host's outbound bytes in one window_seconds bucket far
    exceed its own history.

    Traffic is summed per host (hostname, else internal source IP) into
    fixed buckets aligned to the epoch. Each bucket is compared with an
    exponentially weighted mean/variance of that host's earlier buckets,
    stored in entity_baselines so the baseline grows across uploads. A
    bucket fires when the host has >= params.min_samples prior buckets, at
    least params.min_bytes went out, and the volume is both >=
    params.multiplier × the mean and > mean + params.stddevs × stdev.
    Anomalous buckets are not folded into the baseline, so one exfiltration
    doesn't teach the rule that exfiltration is normal. Traffic to private
    destinations (lateral, backup to an internal NAS) is excluded.

    Needs byte counts per flow/connection: CSV/JSON flow or proxy exports
    with a bytes_out-style column. Firewall packet logs don't carry them.
    """

    name = "egress_volume_anomaly"
    description = "A host sent far more outbound data than its own baseline."
    severity = "HIGH"
    mitre_technique = "T1041"
    entity_type = "host"
    confidence = 55
    DEFAULT_PARAMS = {
        "multiplier": 5.0,
        "stddevs": 3.0,
        "min_bytes": 50_000_000,
        "min_samples": 6,
    }

    def __init__(
        self,
        window_seconds: int = 3600,
        cooldown_seconds: int = 0,
        allowlist: list[str] | None = None,
        params: dict | None = None,
    ):
        self.window_seconds = window_seconds
        self.cooldown_seconds = cooldown_seconds
        self.allowlist = allowlist
        self.params = self.merge_params(params)
        self._allowed = {item.strip() for item in (allowlist or ())}

    def _bucket(self, ts: datetime) -> int:
        epoch = int(ts.astimezone(timezone.utc).timestamp())
        return epoch - epoch % self.window_seconds

    def analyze(self, records: list[LogRecord], db=None) -> list[Alert]:
        buckets: dict[str, dict[int, dict]] = defaultdict(dict)
        for record in records:
            if not record.bytes_out:
                continue
            if record.dest_ip and not is_public_ip(record.dest_ip):
                continue
            internal_ip = record.ip_address if not is_public_ip(record.ip_address) else None
            host = endpoint_id(record, internal_ip)
            if not host or host in self._allowed:
                continue
            ts = parse_ts(record.timestamp)
            if ts is None:
                continue
            bucket = buckets[host].setdefault(self._bucket(ts), {"bytes": 0, "records": [], "destinations": defaultdict(int)})
            bucket["bytes"] += record.bytes_out
            bucket["records"].append(record)
            if record.dest_ip or record.domain:
                bucket["destinations"][record.dest_ip or record.domain] += record.bytes_out

        multiplier = float(self.params["multiplier"])
        stddevs = float(self.params["stddevs"])
        min_bytes = int(self.params["min_bytes"])
        min_samples = int(self.params["min_samples"])
        alerts: list[Alert] = []

        for host, host_buckets in buckets.items():
            stored = (
                get_baseline(db, entity_type="host", entity_id=host, baseline_key=BASELINE_KEY)
                if db is not None else None
            ) or {}
            mean = float(stored.get("mean") or 0.0)
            variance = float(stored.get("variance") or 0.0)
            samples = int(stored.get("samples") or 0)
            last_bucket = stored.get("last_bucket")

            for start in sorted(host_buckets):
                if last_bucket is not None and start <= last_bucket:
                    continue  # already folded in by an earlier upload
                data = host_buckets[start]
                volume = data["bytes"]
                stdev = math.sqrt(variance)
                anomalous = (
                    samples >= min_samples
                    and volume >= min_bytes
                    and volume >= multiplier * mean
                    and volume > mean + stddevs * stdev
                )
                if anomalous:
                    recs = data["records"]
                    top = sorted(data["destinations"].items(), key=lambda item: item[1], reverse=True)[:5]
                    window_start = datetime.fromtimestamp(start, tz=timezone.utc)
                    alerts.append(Alert(
                        rule=self.name,
                        severity=self.severity,
                        source_ip=recs[0].ip_address,
                        hostname=recs[0].hostname,
                        count=len(recs),
                        time_window_seconds=self.window_seconds,
                        first_seen=ts_to_str(window_start),
                        last_seen=ts_to_str(datetime.fromtimestamp(start + self.window_seconds, tz=timezone.utc)),
                        description=(
                            f"Egress spike from {host}: {volume / 1_000_000:.1f} MB out in "
                            f"{self.window_seconds // 60} min vs. a baseline of "
                            f"{mean / 1_000_000:.1f} MB ({volume / mean if mean else float('inf'):.1f}×)."
                        ),
                        matched_line_numbers=[r.line_number for r in recs],
                        mitre_technique=self.mitre_technique,
                        confidence=self.confidence,
                        entity_type=self.entity_type,
                        entity_id=host,
                        evidence={
                            "bytes_out": volume,
                            "baseline_mean_bytes": int(mean),
                            "baseline_stdev_bytes": int(stdev),
                            "baseline_samples": samples,
                            "top_destinations": [{"destination": d, "bytes": b} for d, b in top],
                        },
                    ))
                else:
                    if samples == 0:
                        mean, variance = float(volume), 0.0
                    else:
                        delta = volume - mean
                        mean += _EWMA_ALPHA * delta
                        variance = (1 - _EWMA_ALPHA) * (variance + _EWMA_ALPHA * delta * delta)
                    samples += 1
                last_bucket = start

            if db is not None:
                set_baseline(
                    db,
                    entity_type="host",
                    entity_id=host,
                    baseline_key=BASELINE_KEY,
                    value={"mean": mean, "variance": variance, "samples": samples, "last_bucket": last_bucket},
                )
        return alerts
