"""Seeded synthetic egress traffic for the egress_volume feature set.

Built from scratch against the real feature extractor
(app/ml/features_egress_volume.py:egress_volume_features) and the real
rule's bucketing (BehavioralAnomalyEgressRule.analyze: hourly buckets keyed
by internal host, requires bytes_out set, dest_ip globally routable, source
ip_address NOT globally routable).

IMPORTANT: the TEST-NET ranges threat_log's generator uses (192.0.2.0/24,
198.51.100.0/24, 203.0.113.0/24) are reserved-for-documentation and are NOT
globally routable under Python's ipaddress.is_global (verified). Destination
pools here therefore use real allocated-looking public ranges instead
(104.16.0.0/13-ish, 172.217.0.0/16-ish, 45.33.0.0/16-ish), and source hosts
use 10.0.0.0/8 (always private), so BehavioralAnomalyEgressRule's
is_public_ip gating treats them exactly as intended.

Overlap is built in from the start: attacks draw bytes, destinations and
hours from the same ranges normal hosts already use, with stated departures
(see OVERLAP_ATTACKS below), the same structure as threat_log's v2 population.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

from app.detection.models import LogRecord

BASE = datetime(2026, 1, 5, tzinfo=timezone.utc)

NORMAL_PORTS = {443: "HTTPS", 80: "HTTP"}
CORE_POOL = [f"104.16.{i}.10" for i in range(10, 30)]       # common cloud/SaaS-style destinations
POPULAR_POOL = [f"172.217.{i}.5" for i in range(10, 20)]     # shared across many hosts' core sets
RARE_POOL_BASE = "45.33"                                     # true long-tail destinations

NORMAL_CONN_RANGE = (3, 8)
NORMAL_BYTES_RANGE = (500_000, 5_000_000)
SPIKE_PROB = 0.08
SPIKE_BYTES_RANGE = (20_000_000, 60_000_000)  # legitimate large-transfer spike, same role as threat_log's had_spike

# Pooled hour-of-day weights for when a host's hourly bucket is active.
# Business-hours weighted but with a real overnight tail (backups, batch
# jobs, follow-the-sun) so off-hours egress is not automatically rare.
HOUR_WEIGHTS = {h: (6 if 8 <= h <= 18 else 2 if h in (6, 7, 19, 20) else 1) for h in range(24)}
DEEP_TAIL_HOURS = (2, 3, 4)       # never assigned to normal buckets -- loud offhour attacks live here
EDGE_HOURS = (5, 21)              # lowest-weight populated hours -- subtle offhour attacks live here

NOVELTY_PROB = 0.10  # baseline chance a bucket visits a destination outside the host's core set


class RecordFactory:
    """Builds LogRecords with a per-scenario line counter."""

    def __init__(self) -> None:
        self._line = 0

    def mk(self, day_offset: int, hour: int, minute: int, second: int, source_ip: str, dest_ip: str, bytes_out: int) -> LogRecord:
        self._line += 1
        ts = BASE.replace(hour=hour, minute=minute, second=second) + timedelta(days=day_offset)
        port = 443
        return LogRecord(
            line_number=self._line, timestamp=ts.strftime("%Y-%m-%dT%H:%M:%SZ"), ip_address=source_ip,
            dest_ip=dest_ip, protocol=NORMAL_PORTS[port], port=port, bytes_out=bytes_out,
        )


class RarePool:
    def __init__(self) -> None:
        self._counter = 0

    def next(self) -> str:
        self._counter += 1
        third = (self._counter // 254) % 50
        fourth = (self._counter % 254) + 1
        return f"{RARE_POOL_BASE}.{third}.{fourth}"


def make_profile(rng: random.Random) -> dict:
    core = rng.sample(CORE_POOL, k=rng.randint(2, 4))
    return {"core": core, "seen": set(core)}


def _weighted_hour(rng: random.Random) -> int:
    keys = list(HOUR_WEIGHTS)
    return rng.choices(keys, weights=[HOUR_WEIGHTS[k] for k in keys], k=1)[0]


def normal_bucket(
    factory: RecordFactory, rng: random.Random, rare_pool: RarePool, profile: dict, host: str, day_offset: int,
    hour: int | None = None,
) -> tuple[list[LogRecord], dict]:
    """One hourly bucket of normal egress for one host, on one day."""

    hour = _weighted_hour(rng) if hour is None else hour
    novel = rng.random() < NOVELTY_PROB
    dest = None
    if novel:
        candidate = rng.choice(POPULAR_POOL) if rng.random() < 0.6 else rare_pool.next()
        if candidate not in profile["seen"]:
            dest = candidate
            profile["seen"].add(candidate)

    n_conn = rng.randint(*NORMAL_CONN_RANGE)
    records: list[LogRecord] = []
    destinations = set()
    total_bytes = 0
    for i in range(n_conn):
        d = dest if (dest and i == 0) else rng.choice(profile["core"])
        destinations.add(d)
        b = max(1, rng.randint(*NORMAL_BYTES_RANGE) // n_conn)
        total_bytes += b
        records.append(factory.mk(day_offset, hour, rng.randint(0, 59), i, host, d, b))

    had_spike = rng.random() < SPIKE_PROB
    if had_spike:
        spike_dest = rng.choice(profile["core"])
        spike_bytes = rng.randint(*SPIKE_BYTES_RANGE)
        records.append(factory.mk(day_offset, hour, 59, 59, host, spike_dest, spike_bytes))
        destinations.add(spike_dest)
        total_bytes += spike_bytes

    meta = {
        "had_novel_dest": dest is not None, "had_spike": had_spike,
        "bytes_total": total_bytes, "connection_count": len(records), "distinct_destinations": len(destinations), "hour": hour,
    }
    return records, meta


# ------------------------------------------------------------ overlap attacks
#
# Named departures from the shared normal vocabulary, stated explicitly:
#   - volume_loud:    bytes just above SPIKE_BYTES_RANGE's ceiling, normal conns/dests/hour
#   - volume_subtle:  bytes at the top of SPIKE_BYTES_RANGE, normal conns/dests/hour
#   - spread_loud:    12 distinct destinations (core set is 2-4), normal bytes/hour
#   - spread_subtle:  6 distinct destinations, normal bytes/hour
#   - offhour_loud:   normal bytes/conns/dests, hour from DEEP_TAIL_HOURS
#   - offhour_subtle: normal bytes/conns/dests, hour from EDGE_HOURS
#   - popular_dest_exfil (guard case): large transfer to a destination common across
#     many OTHER hosts in the scenario -- no org-wide destination-rarity feature
#     exists, so this is expected to evade (same blind spot as threat_log's exfil_popular)

OVERLAP_ATTACKS = ("volume_loud", "volume_subtle", "spread_loud", "spread_subtle", "offhour_loud", "offhour_subtle")


def overlap_attack_records(
    factory: RecordFactory, rng: random.Random, name: str, host: str, day_offset: int, *, core: list[str],
) -> tuple[list[LogRecord], dict]:
    hour = _weighted_hour(rng)
    records: list[LogRecord] = []
    if name == "volume_loud":
        b = rng.randint(65_000_000, 90_000_000)
        records.append(factory.mk(day_offset, hour, 30, 0, host, rng.choice(core), b))
        meta = {"bytes_total": b, "connection_count": 1, "distinct_destinations": 1, "hour": hour}
    elif name == "volume_subtle":
        b = rng.randint(55_000_000, 60_000_000)
        records.append(factory.mk(day_offset, hour, 30, 0, host, rng.choice(core), b))
        meta = {"bytes_total": b, "connection_count": 1, "distinct_destinations": 1, "hour": hour}
    elif name in ("spread_loud", "spread_subtle"):
        n_dest = 12 if name == "spread_loud" else 6
        dests = [rng.choice(POPULAR_POOL) for _ in range(n_dest)]
        total = 0
        for i, d in enumerate(dests):
            b = max(1, rng.randint(*NORMAL_BYTES_RANGE) // n_dest)
            total += b
            records.append(factory.mk(day_offset, hour, rng.randint(0, 59), i, host, d, b))
        meta = {"bytes_total": total, "connection_count": len(dests), "distinct_destinations": len(set(dests)), "hour": hour}
    else:  # offhour_loud / offhour_subtle
        hour = rng.choice(DEEP_TAIL_HOURS if name == "offhour_loud" else EDGE_HOURS)
        n_conn = rng.randint(*NORMAL_CONN_RANGE)
        total = 0
        dests = set()
        for i in range(n_conn):
            d = rng.choice(core)
            dests.add(d)
            b = max(1, rng.randint(*NORMAL_BYTES_RANGE) // n_conn)
            total += b
            records.append(factory.mk(day_offset, hour, rng.randint(0, 59), i, host, d, b))
        meta = {"bytes_total": total, "connection_count": n_conn, "distinct_destinations": len(dests), "hour": hour}
    return records, meta


def guard_case_records(
    factory: RecordFactory, rng: random.Random, host: str, day_offset: int, *, popular_dest: str,
) -> tuple[list[LogRecord], dict]:
    """popular_dest_exfil: one large transfer to a destination common across other
    hosts' core sets. Hour drawn from the common weighted pool so only the
    (missing) org-wide destination-rarity signal is being tested."""

    hour = _weighted_hour(rng)
    b = rng.randint(*SPIKE_BYTES_RANGE)
    record = factory.mk(day_offset, hour, 15, 0, host, popular_dest, b)
    return [record], {"bytes_total": b, "connection_count": 1, "distinct_destinations": 1, "hour": hour}


def host_egress_features(records: list[LogRecord]) -> dict[str, float]:
    """Diagnostic summary of one host's bucket: raw bytes total (not log-scaled),
    connection count, distinct destination count, raw hour. Not the model's actual
    (log-scaled) inputs; used only for the single-feature-AUC proof."""

    if not records:
        return {"bytes_total": 0.0, "connection_count": 0.0, "distinct_destinations": 0.0, "hour": 0.0}
    hour = int(records[0].timestamp[11:13])
    return {
        "bytes_total": float(sum(r.bytes_out for r in records)),
        "connection_count": float(len(records)),
        "distinct_destinations": float(len({r.dest_ip for r in records})),
        "hour": float(hour),
    }
