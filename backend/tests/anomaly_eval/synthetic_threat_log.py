"""Seeded synthetic traffic for the threat_log feature set.

Ported from ml_experiments/threat_log_false_positive_power_check.py with the
generator logic and RNG call order unchanged, so the same seeds reproduce the
same populations (this is what the parity check relies on). The one structural
change: the line-number counter is per-factory instead of module-global, so
scenarios share no state. Line numbers are never model features.
"""

from __future__ import annotations

import itertools
import random
from datetime import datetime, timezone

from app.detection.models import LogRecord

BASE = datetime(2026, 1, 5, tzinfo=timezone.utc)
NORMAL_PORTS = {443: "HTTPS", 80: "HTTP"}
CORE_POOL = [f"198.51.100.{i}" for i in range(10, 30)]
POPULAR_POOL = [f"192.0.2.{i}" for i in range(10, 20)]
SPIKE_PROB = 0.08
DENY_RATE_RANGE = (0.05, 0.20)


def _ts(hour: int, minute: int, second: int = 0) -> str:
    return BASE.replace(hour=hour, minute=minute, second=second).strftime("%Y-%m-%dT%H:%M:%SZ")


class RecordFactory:
    """Builds LogRecords with a per-scenario line counter."""

    def __init__(self) -> None:
        self._lines = itertools.count(1)

    def mk(self, ts_str: str, source_ip: str, dest_ip: str, protocol: str, port: int, bytes_out: int, status: str) -> LogRecord:
        return LogRecord(
            line_number=next(self._lines), timestamp=ts_str, ip_address=source_ip, dest_ip=dest_ip,
            protocol=protocol, port=port, bytes_out=bytes_out, status=status,
        )


class RarePool:
    """True long-tail destinations, disjoint from CORE_POOL/POPULAR_POOL and
    from every attack generator's fixed destinations (203.0.113.x)."""

    def __init__(self) -> None:
        self._counter = 0

    def next(self) -> str:
        self._counter += 1
        third = (self._counter // 254) % 50
        fourth = (self._counter % 254) + 1
        return f"198.18.{third}.{fourth}"


def make_profile(rng: random.Random) -> dict:
    core = rng.sample(CORE_POOL, k=rng.randint(2, 3))
    return {"core": core, "deny_rate": rng.uniform(*DENY_RATE_RANGE), "seen": set(core)}


def realistic_bucket_records(
    factory: RecordFactory, rng: random.Random, rare_pool: RarePool, profile: dict, source_ip: str, hour: int,
    novelty_level: float,
) -> tuple[list[LogRecord], dict]:
    novel_this_bucket = rng.random() < novelty_level
    new_dests: list[str] = []
    if novel_this_bucket:
        for _ in range(rng.randint(1, 3)):
            candidate = rng.choice(POPULAR_POOL) if rng.random() < 0.7 else rare_pool.next()
            if candidate not in profile["seen"]:
                new_dests.append(candidate)
                profile["seen"].add(candidate)

    records = []
    statuses = []
    for i in range(rng.randint(3, 6)):
        dest = rng.choice(new_dests) if new_dests and rng.random() < 0.5 else rng.choice(profile["core"])
        port = rng.choice(list(NORMAL_PORTS))
        status = "DENIED" if rng.random() < profile["deny_rate"] else "ALLOWED"
        statuses.append(status)
        records.append(factory.mk(
            _ts(hour, minute=rng.randint(0, 59), second=i), source_ip, dest,
            NORMAL_PORTS[port], port, rng.randint(2_000, 20_000), status,
        ))

    had_spike = rng.random() < SPIKE_PROB
    if had_spike:
        spike_dest = rng.choice(profile["core"] + POPULAR_POOL)
        records.append(factory.mk(
            _ts(hour, minute=59, second=59), source_ip, spike_dest,
            "HTTPS", 443, rng.randint(100_000_000, 300_000_000), "ALLOWED",
        ))
        statuses.append("ALLOWED")

    denied = sum(1 for s in statuses if s == "DENIED")
    meta = {
        "had_novel_dest": bool(new_dests),
        "new_dest_count": len(new_dests),
        "had_spike": had_spike,
        "observed_deny_rate": (denied / len(statuses)) if statuses else 0.0,
        "assigned_deny_rate": profile["deny_rate"],
    }
    return records, meta


def port_scan_records(factory: RecordFactory, source_ip: str, hour: int, *, dest: str, num_ports: int) -> list[LogRecord]:
    return [
        factory.mk(_ts(hour, minute=i % 60), source_ip, dest, "TCP", 20_000 + i, 100, "ALLOWED")
        for i in range(num_ports)
    ]


def big_transfer_records(factory: RecordFactory, source_ip: str, hour: int, *, dest: str, bytes_out: int, count: int) -> list[LogRecord]:
    return [
        factory.mk(_ts(hour, minute=5 * i), source_ip, dest, "HTTPS", 443, bytes_out, "ALLOWED")
        for i in range(count)
    ]


def deny_burst_records(
    factory: RecordFactory, source_ip: str, hour: int, *, dest: str, count: int, deny_fraction: float,
) -> list[LogRecord]:
    denied_count = round(count * deny_fraction)
    return [
        factory.mk(_ts(hour, minute=i % 60), source_ip, dest, "HTTPS", 443, 500, "DENIED" if i < denied_count else "ALLOWED")
        for i in range(count)
    ]


# ------------------------------------------------------------ population v2: overlap
#
# v1 (the functions above, `population="v1"`) made attacks separable by
# construction: port scans on ports 20000+ that normal traffic never uses,
# single-destination attacks while normal IPs use 2-3, byte volumes 4-10x above
# the normal spike range, and deny rates of 40-100% against a normal 5-20%.
#
# v2 builds attacks from the same vocabulary as normal traffic: common ports,
# the normal core destinations (plus a shared popular destination), and byte
# sizes inside the normal spike range. Overlap is not total, and the departures
# are stated here rather than implied:
#   - loud scan: 10 records, above the normal 3-6 per bucket
#   - loud transfer: 150-250MB, inside the normal 100-300MB spike range
#   - loud deny burst: 35% denied, above the normal 5-20% assigned range
#   - subtle scan: 5 records, inside the normal range
#   - subtle transfer: 90-110MB, straddling the normal 100MB spike floor
#   - subtle deny burst: 20% denied, the top of the normal range
# Normal traffic is unchanged from v1.

def overlap_port_scan_records(
    factory: RecordFactory, rng: random.Random, source_ip: str, hour: int, *, dests: list[str], count: int,
) -> list[LogRecord]:
    """Short bursts of ordinary web connections across a few core destinations."""

    records = []
    for i in range(count):
        port = rng.choice(list(NORMAL_PORTS))
        records.append(factory.mk(
            _ts(hour, minute=rng.randint(0, 59), second=i), source_ip, rng.choice(dests),
            NORMAL_PORTS[port], port, rng.randint(2_000, 20_000), "ALLOWED",
        ))
    return records


def overlap_transfer_records(
    factory: RecordFactory, rng: random.Random, source_ip: str, hour: int, *, dest: str, byte_range: tuple[int, int], count: int,
) -> list[LogRecord]:
    """Large web transfers, sized inside or just below the normal spike range.
    Port is drawn from the same common ports as normal traffic, not fixed."""

    records = []
    for i in range(count):
        port = rng.choice(list(NORMAL_PORTS))
        records.append(factory.mk(
            _ts(hour, minute=rng.randint(0, 59), second=i), source_ip, dest,
            NORMAL_PORTS[port], port, rng.randint(*byte_range), "ALLOWED",
        ))
    return records


def overlap_deny_burst_records(
    factory: RecordFactory, rng: random.Random, source_ip: str, hour: int, *, dests: list[str], count: int, deny_rate: float,
) -> list[LogRecord]:
    """Ordinary-looking web traffic with an elevated deny rate (see the departures above).
    Port is drawn from the same common ports as normal traffic, not fixed."""

    records = []
    for i in range(count):
        status = "DENIED" if rng.random() < deny_rate else "ALLOWED"
        port = rng.choice(list(NORMAL_PORTS))
        records.append(factory.mk(
            _ts(hour, minute=rng.randint(0, 59), second=i), source_ip, rng.choice(dests),
            NORMAL_PORTS[port], port, rng.randint(2_000, 20_000), status,
        ))
    return records


# Per-attack parameters for population v2. Kept here, next to the generators,
# so the moderate setting is visible in one place.
OVERLAP_SPIKE_RANGE = (100_000_000, 300_000_000)  # the normal spike range in make_profile / realistic_bucket_records
OVERLAP_ATTACKS = {
    # name: (kind, parameters)
    "port_scan_loud": ("scan", {"count": 10}),
    "big_transfer_loud": ("transfer", {"byte_range": (150_000_000, 250_000_000), "count": 2}),
    "deny_burst_loud": ("deny", {"count": 12, "deny_rate": 0.35}),
    "port_scan_subtle": ("scan", {"count": 5}),
    "big_transfer_subtle": ("transfer", {"byte_range": (90_000_000, 110_000_000), "count": 1}),
    "deny_burst_subtle": ("deny", {"count": 6, "deny_rate": 0.20}),
}


def overlap_attack_records(
    factory: RecordFactory, rng: random.Random, name: str, source_ip: str, hour: int, *, core: list[str],
) -> list[LogRecord]:
    """Records for one named v2 attack. `core` is the source IP's own normal core destinations."""

    kind, params = OVERLAP_ATTACKS[name]
    if kind == "scan":
        return overlap_port_scan_records(factory, rng, source_ip, hour, dests=core, count=params["count"])
    if kind == "transfer":
        # Loud transfers go to a destination many normal IPs already use, so the
        # destination itself is not evidence of an attack.
        dest = rng.choice(POPULAR_POOL) if name.startswith("big_transfer_loud") else rng.choice(core)
        return overlap_transfer_records(factory, rng, source_ip, hour, dest=dest, byte_range=params["byte_range"], count=params["count"])
    return overlap_deny_burst_records(factory, rng, source_ip, hour, dests=core, count=params["count"], deny_rate=params["deny_rate"])


def ip_features(records: list[LogRecord]) -> dict[str, float]:
    """Summary features of one IP's test-period records. Diagnostic only: these are
    not the model's inputs. They measure how separable each population is on a
    single, easy-to-read feature, which is the check the v1 study lacked."""

    count = len(records)
    if not count:
        return {"record_count": 0, "distinct_dests": 0, "distinct_ports": 0, "bytes_total": 0, "deny_rate": 0.0}
    return {
        "record_count": count,
        "distinct_dests": len({r.dest_ip for r in records}),
        "distinct_ports": len({r.port for r in records}),
        "bytes_total": sum(r.bytes_out for r in records),
        "deny_rate": sum(1 for r in records if r.status == "DENIED") / count,
    }
