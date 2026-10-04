"""Scenario runners: build history, train, inject anomalies, return plain scores.

Results are plain Python data (floats and strings, never ORM rows) so they stay
valid after the scenario's savepoint is rolled back.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field

from sqlalchemy.orm import Session

from tests.anomaly_eval import synthetic_threat_log as tl
from tests.anomaly_eval.harness import SPECS, isolated_scenario


@dataclass
class ScenarioResult:
    key: str
    seed: int
    shipped_threshold: float
    normal: dict[str, float]  # entity id -> score at the evaluation period
    attacks: dict[str, float]  # injected-attack name -> score
    meta: dict = field(default_factory=dict)

    def attacks_where(self, suffix: str) -> dict[str, float]:
        return {name: score for name, score in self.attacks.items() if name.endswith(suffix)}


# -------------------------------------------------------------- threat_log

THREAT_LOG_ATTACKS = (
    "port_scan_loud", "big_transfer_loud", "deny_burst_loud",
    "port_scan_subtle", "big_transfer_subtle", "deny_burst_subtle",
    "exfil_popular",
)


POPULATIONS = ("v1", "v2")


def run_threat_log_scenario(
    db: Session, *, novelty_level: float, seed: int, level_idx: int = 0, n_normal: int = 100, population: str = "v2",
) -> ScenarioResult:
    """One (novelty_level, seed) scenario: n_normal ordinary IPs plus 7 attack IPs
    (3 loud, 3 subtle, 1 exfil-to-popular-destination guard case).

    `population="v2"` (default) uses overlapping attacks; `"v1"` reproduces the
    separable attacks of the original study. Normal traffic is identical in both.

    Mirrors run_once() in ml_experiments/threat_log_false_positive_power_check.py,
    with isolation provided by the harness instead of by hand.
    """

    if population not in POPULATIONS:
        raise ValueError(f"population must be one of {POPULATIONS}, got {population!r}")
    label = f"n{int(novelty_level * 100)}-s{seed}"
    with isolated_scenario(db, "threat_log", label=label) as scenario:
        factory = tl.RecordFactory()
        rng = random.Random(seed * 1000 + level_idx)
        rare_pool = tl.RarePool()
        ip_base = f"10.{200 + level_idx}.{seed}"
        normal_ips = [f"{ip_base}.{i}" for i in range(1, n_normal + 1)]
        attack_ips = {name: f"{ip_base}.{100 + j}" for j, name in enumerate(THREAT_LOG_ATTACKS, start=1)}
        all_ips = normal_ips + list(attack_ips.values())
        profiles = {ip: tl.make_profile(rng) for ip in all_ips}

        rule = scenario.rule()

        history: list = []
        for hour in range(6):
            for ip in all_ips:
                records, _meta = tl.realistic_bucket_records(factory, rng, rare_pool, profiles[ip], ip, hour, novelty_level)
                history += records
        rule.analyze(history, db)
        assert scenario.snapshot_count() >= SPECS["threat_log"].min_samples
        scenario.train()

        test_records: list = []
        injection_meta: dict[str, dict] = {}
        for ip in normal_ips:
            records, meta = tl.realistic_bucket_records(factory, rng, rare_pool, profiles[ip], ip, hour=6, novelty_level=novelty_level)
            test_records += records
            injection_meta[ip] = meta

        if population == "v1":
            test_records += tl.port_scan_records(factory, attack_ips["port_scan_loud"], hour=6, dest=tl.CORE_POOL[0], num_ports=25)
            test_records += tl.big_transfer_records(
                factory, attack_ips["big_transfer_loud"], hour=6, dest="203.0.113.77", bytes_out=800_000_000, count=2,
            )
            test_records += tl.deny_burst_records(
                factory, attack_ips["deny_burst_loud"], hour=6, dest=tl.CORE_POOL[0], count=20, deny_fraction=1.0,
            )
            test_records += tl.port_scan_records(factory, attack_ips["port_scan_subtle"], hour=6, dest=tl.CORE_POOL[1], num_ports=5)
            test_records += tl.big_transfer_records(
                factory, attack_ips["big_transfer_subtle"], hour=6, dest="203.0.113.88", bytes_out=50_000_000, count=1,
            )
            test_records += tl.deny_burst_records(
                factory, attack_ips["deny_burst_subtle"], hour=6, dest=tl.CORE_POOL[1], count=20, deny_fraction=0.4,
            )
        else:
            for name in tl.OVERLAP_ATTACKS:
                ip = attack_ips[name]
                test_records += tl.overlap_attack_records(factory, rng, name, ip, 6, core=profiles[ip]["core"])

        # Exfil to a destination many normal IPs already use: per-IP novelty still
        # fires, but the destination is not rare across the organisation.
        exfil_ip = attack_ips["exfil_popular"]
        exfil_dest = next(d for d in tl.POPULAR_POOL if d not in profiles[exfil_ip]["seen"])
        popularity = sum(1 for ip in normal_ips if exfil_dest in profiles[ip]["seen"])
        test_records += tl.big_transfer_records(factory, exfil_ip, hour=6, dest=exfil_dest, bytes_out=500_000_000, count=1)

        rule.analyze(test_records, db)
        latest = scenario.latest_scores()
        by_ip: dict[str, list] = {}
        for record in test_records:
            by_ip.setdefault(record.ip_address, []).append(record)

        return ScenarioResult(
            key="threat_log",
            seed=seed,
            shipped_threshold=SPECS["threat_log"].shipped_threshold(),
            normal={ip: latest[ip] for ip in normal_ips},
            attacks={name: latest[ip] for name, ip in attack_ips.items()},
            meta={
                "novelty_level": novelty_level,
                "population": population,
                "exfil_dest_popularity": popularity,
                "injection_meta": injection_meta,
                # Test-period summary features per IP, for the single-feature diagnostic only.
                "features": {ip: tl.ip_features(by_ip[ip]) for ip in normal_ips + list(attack_ips.values())},
                "attack_ips": attack_ips,
            },
        )
