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
