"""
Feature extraction for the threat-log IsolationForest pilot.

Grew out of the offline ml_experiments/ evaluation across 5 unrelated CSV
datasets (see ml_experiments/reports/threat_detection_logs.txt): of the
five, only cybersecurity_threat_detection_logs.csv showed its label
correlated with observable traffic features (ROC-AUC 0.72 vs. ~0.5 for the
rest). That dataset's own feature prep (frequency-encoded IPs/paths plus
one-hot protocol/action/user_agent, see ml_experiments/train_isolation_forest.py)
doesn't fit this pipeline's fixed-width feature_names contract — one-hot
columns are data-dependent on whatever categories happen to appear in a
given training run, so model versions wouldn't stay comparable over time.

This reimplements the same underlying signal as a small fixed set derivable
from any firewall/netflow/proxy export, the same contract
egress_volume_features already relies on, plus a second generation of
features added after a follow-up offline eval
(ml_experiments/eval_production_threat_log_features.py) found the first
5-feature version only reached ROC-AUC ~0.53 on that same CSV (vs. 0.72 for
the one-hot baseline) — most of the one-hot model's power came from
per-row protocol/action/user_agent categories and per-row IP/path frequency,
exactly what a fixed schema can't carry directly. The `*_rarity`,
`new_*_rate`, and `*_entropy` features below are this pipeline's fixed-width
answer to that same idea: not "which protocol" but "how surprising is this
bucket's mix of destinations/ports/protocols given this source IP's own
history" — the same "have we seen this before" judgment
first_seen_geo_asn/login_behavior's `is_new_geo` already uses, generalized
from a yes/no flag to a continuous rarity score and applied to three
dimensions instead of one.

No time-of-day feature: every row in that CSV carries hour=0 — cyclic
hour/day-of-week features were dead weight there (removing them made no
measurable difference either way; see the eval script's reports). Any log
source this rule runs against in production may have real intra-day
timing, but there's no offline evidence either way yet, so this leaves
time out rather than carry an untested feature pair.

Caveat recorded in the eval script's docstring, not fixed here: the offline
label used to score any of this (`threat_label != benign` at the row level,
OR'd up to "any row in this bucket is non-benign") correlates with bucket
size on its own -- bucket size (connection_count) alone reaches ROC-AUC
~0.66 on that label with zero behavioral signal, because a bigger bucket
has more chances to contain a labeled row by chance. That confound sits
under every number in these reports equally (the baseline's per-row
features, and both generations of these bucketed features all include
`connection_count`/an equivalent), so it doesn't favor one feature design
over another, but it does mean the absolute ROC-AUC numbers overstate how
much genuine behavioral signal any of these features carry.
"""

from __future__ import annotations

import math

FEATURE_SET = "threat_log"
ENTITY_TYPE = "source_ip"

# How many distinct values (per dimension) one source IP's running history
# remembers. An IP that talks to thousands of distinct destinations would
# otherwise grow this baseline row without bound; capping to the
# most-frequent HISTORY_CAP values keeps rarity/novelty scoring against "the
# values this IP actually uses regularly" rather than a complete log,
# trading perfect recall on one-off historical destinations for a bounded
# baseline row (same tradeoff first_seen_geo_asn's own _MAX_REMEMBERED makes).
HISTORY_CAP = 200

FEATURE_NAMES: tuple[str, ...] = (
    "log_bytes_total", "connection_count", "distinct_destinations", "distinct_ports", "deny_rate",
    "dest_rarity", "port_rarity", "protocol_rarity",
    "new_destination_rate", "new_port_rate",
    "dest_entropy", "port_entropy",
)


def empty_history() -> dict:
    """The starting baseline for a source IP this pilot has never scored before."""

    return {"dest_counts": {}, "port_counts": {}, "protocol_counts": {}, "total": 0}


def _entropy(counts: dict[str, int]) -> float:
    """Shannon entropy (bits) of one bucket's own value distribution — how
    spread out its connections are across distinct values on this dimension.
    A bucket hitting one destination/port over and over scores 0; one
    spreading evenly across many scores higher (fan-out, sweep-like)."""

    total = sum(counts.values())
    if total <= 0:
        return 0.0
    entropy = 0.0
    for count in counts.values():
        if count <= 0:
            continue
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def _rarity(bucket_counts: dict[str, int], history_counts: dict[str, int], history_total: int) -> float:
    """Connection-weighted average surprisal (bits) of this bucket's values
    against the source IP's own historical frequency for that dimension,
    Laplace-smoothed so a value with zero prior history doesn't produce a
    division by zero or an infinite score -- it's simply the most surprising
    outcome representable at the current history size, which grows more
    confident (more bits) the longer the history behind it."""

    bucket_total = sum(bucket_counts.values())
    if bucket_total <= 0:
        return 0.0
    surprisal = 0.0
    for value, count in bucket_counts.items():
        p = (history_counts.get(value, 0) + 1) / (history_total + 1)
        surprisal += count * -math.log2(p)
    return surprisal / bucket_total


def _novel_rate(bucket_values: set[str], history_counts: dict[str, int]) -> float:
    """Fraction of this bucket's distinct values never seen in this source
    IP's history at all -- a blunter, more human-readable companion to
    `_rarity` above (a value this IP uses rarely but has used before scores
    some rarity but 0 novelty; a value it has truly never used scores both)."""

    if not bucket_values:
        return 0.0
    novel = sum(1 for value in bucket_values if value not in history_counts)
    return novel / len(bucket_values)


def threat_log_features(
    *, bytes_total: int, connection_count: int, denied_count: int,
    dest_counts: dict[str, int], port_counts: dict[str, int], protocol_counts: dict[str, int],
    history: dict,
) -> dict[str, float]:
    """
    One feature vector for one source IP's hourly traffic bucket.

    `dest_counts`/`port_counts`/`protocol_counts` are this bucket's own
    within-bucket frequency tables (string keys — ports as str so they
    round-trip through the JSON-backed baseline row the same way). `history`
    is that source IP's running baseline *as of just before this bucket*
    (see `update_history` below) -- never including this bucket's own
    events, so a bucket can't make itself look less surprising by being
    scored against itself.

    `bytes_total` is log1p-scaled for the same reason egress_volume_features
    log-scales bytes_out — raw byte counts span orders of magnitude.
    `deny_rate` is denied_count / connection_count: a host making many
    connections that are mostly rejected (sweep, scan, blocked exfil
    attempt) looks different from the same volume mostly allowed.
    """

    history_total = int(history.get("total", 0))
    return {
        "log_bytes_total": math.log1p(max(0, bytes_total)),
        "connection_count": float(connection_count),
        "distinct_destinations": float(len(dest_counts)),
        "distinct_ports": float(len(port_counts)),
        "deny_rate": (denied_count / connection_count) if connection_count else 0.0,
        "dest_rarity": _rarity(dest_counts, history.get("dest_counts", {}), history_total),
        "port_rarity": _rarity(port_counts, history.get("port_counts", {}), history_total),
        "protocol_rarity": _rarity(protocol_counts, history.get("protocol_counts", {}), history_total),
        "new_destination_rate": _novel_rate(set(dest_counts), history.get("dest_counts", {})),
        "new_port_rate": _novel_rate(set(port_counts), history.get("port_counts", {})),
        "dest_entropy": _entropy(dest_counts),
        "port_entropy": _entropy(port_counts),
    }


def update_history(
    history: dict, *, dest_counts: dict[str, int], port_counts: dict[str, int],
    protocol_counts: dict[str, int], connection_count: int,
) -> dict:
    """Fold one bucket's counts into the running per-source-IP baseline,
    after that bucket has already been scored against the pre-update
    version of `history` — call this strictly after `threat_log_features`,
    never before, or a bucket ends up scored against itself."""

    def _merge(existing: dict[str, int], bucket_counts: dict[str, int]) -> dict[str, int]:
        merged = dict(existing)
        for value, count in bucket_counts.items():
            merged[value] = merged.get(value, 0) + count
        if len(merged) > HISTORY_CAP:
            merged = dict(sorted(merged.items(), key=lambda kv: -kv[1])[:HISTORY_CAP])
        return merged

    return {
        "dest_counts": _merge(history.get("dest_counts", {}), dest_counts),
        "port_counts": _merge(history.get("port_counts", {}), port_counts),
        "protocol_counts": _merge(history.get("protocol_counts", {}), protocol_counts),
        "total": int(history.get("total", 0)) + connection_count,
    }


def vector(features: dict[str, float], feature_names: list[str] | tuple[str, ...] = FEATURE_NAMES) -> list[float]:
    return [float(features[name]) for name in feature_names]
