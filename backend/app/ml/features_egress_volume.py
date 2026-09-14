"""
Feature extraction for the egress-volume IsolationForest pilot.

Pilot #2 from the feasibility doc — explicitly called out there as the best
candidate, since it already had the closest thing to a feature history
(EgressVolumeAnomalyRule's own EWMA mean/variance of one dimension, bytes
per window). This scores the same hourly per-host bucket jointly across
volume, destination spread, connection count, and time of day — catching a
combination none of those alone would flag, the same idea as pilot #1.
"""

from __future__ import annotations

import math
from datetime import datetime, timezone

FEATURE_SET = "egress_volume"
ENTITY_TYPE = "host"

FEATURE_NAMES: tuple[str, ...] = (
    "log_bytes_out", "connection_count", "distinct_destinations", "hour_sin", "hour_cos",
)


def egress_volume_features(
    ts: datetime, *, bytes_out: int, connection_count: int, distinct_destinations: int
) -> dict[str, float]:
    """
    One feature vector for one host's hourly egress bucket.

    `bytes_out` is log1p-scaled — raw byte counts span orders of magnitude
    (kilobytes to gigabytes), and IsolationForest's random-split partitioning
    works on whatever scale it's given; log-scaling keeps a 10x-vs-100x jump
    comparably "sized" to the other features instead of one dimension
    swamping the split geometry.
    """

    utc = ts.astimezone(timezone.utc)
    hour = utc.hour + utc.minute / 60
    return {
        "log_bytes_out": math.log1p(max(0, bytes_out)),
        "connection_count": float(connection_count),
        "distinct_destinations": float(distinct_destinations),
        "hour_sin": math.sin(2 * math.pi * hour / 24),
        "hour_cos": math.cos(2 * math.pi * hour / 24),
    }


def vector(features: dict[str, float], feature_names: list[str] | tuple[str, ...] = FEATURE_NAMES) -> list[float]:
    return [float(features[name]) for name in feature_names]
