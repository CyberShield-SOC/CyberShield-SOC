"""Scenario runners: build history, train, inject anomalies, return plain scores.

Results are plain Python data (floats and strings, never ORM rows) so they stay
valid after the scenario's savepoint is rolled back.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field

from sqlalchemy.orm import Session

from tests.anomaly_eval import synthetic_egress as eg
from tests.anomaly_eval import synthetic_login as lg
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


# -------------------------------------------------------------- login

LOGIN_ATTACKS = (
    "odd_hour_loud", "odd_hour_subtle", "new_geo_loud", "new_geo_subtle",
    "combined_loud", "combined_subtle", "new_geo_common_country",
)
LOGIN_GUARD_CASE = "new_geo_common_country"


def run_login_scenario(
    db: Session, *, seed: int, n_normal: int = 100, history_days: int = 14, logins_per_user: int = 5,
    population: str = "v2",
) -> ScenarioResult:
    """One seeded scenario: n_normal accounts with their own login history, plus 7
    attack accounts (3 loud/subtle pairs + 1 new-geo-common-country guard case).

    Same shape as run_threat_log_scenario: build history, train, inject a test
    period, read back scores. Mirrors synthetic_login.py's overlap design.
    """

    if population != "v2":
        raise ValueError(f"login only has population 'v2', got {population!r}")
    label = f"s{seed}"
    with isolated_scenario(db, "login", label=label) as scenario:
        factory = lg.RecordFactory()
        rng = random.Random(seed * 1000)
        acct_base = f"acct-{seed}"
        normal_users = [f"{acct_base}-{i}" for i in range(1, n_normal + 1)]
        attack_users = {name: f"{acct_base}-atk-{name}" for name in LOGIN_ATTACKS}
        profiles = {u: lg.make_profile(rng) for u in normal_users}
        # Decided now (from each profile's fixed primary home, not the
        # history-mutated "seen" set) so it's stable before any history runs:
        # the guard-case attacker's own home country must differ from it, or
        # its "new for this account, common org-wide" premise collapses into
        # "just this account's own known country" for the seeds where they'd
        # otherwise coincide.
        common_country = max(
            lg.HOME_COUNTRIES, key=lambda c: sum(1 for u in normal_users if profiles[u]["home"][0] == c),
        )
        attacker_home = {u: rng.choice(lg.HOME_COUNTRIES) for u in attack_users.values()}
        guard_user = attack_users[LOGIN_GUARD_CASE]
        if attacker_home[guard_user] == common_country:
            attacker_home[guard_user] = rng.choice([c for c in lg.HOME_COUNTRIES if c != common_country])

        rule = scenario.rule()

        history: list = []
        for user in normal_users:
            for _ in range(logins_per_user):
                day = lg.weighted_day_offset(rng, history_days)
                records, _meta = lg.normal_login_records(factory, rng, profiles[user], user, day)
                history += records
        # Attacker accounts need their own baseline history too -- a few plain,
        # no-travel logins at their assigned home country, establishing it as
        # "known" before the test period. Without this, every attacker's
        # known_countries baseline is empty and is_new_geo computes to True
        # unconditionally for all of them, regardless of the attack's intended
        # new_geo_rate (see attacker_baseline_record's docstring).
        for user in attack_users.values():
            for _ in range(3):
                day = lg.weighted_day_offset(rng, history_days)
                history.append(lg.attacker_baseline_record(factory, rng, user, day, home_country=attacker_home[user]))
        rule.analyze(history, db)
        assert scenario.snapshot_count() >= SPECS["login"].min_samples, (
            f"only {scenario.snapshot_count()} login snapshots, need >= {SPECS['login'].min_samples} to train"
        )
        scenario.train()

        test_day = history_days  # one calendar day after the history window
        test_records: list = []
        injection_meta: dict[str, dict] = {}
        diagnostic_features: dict[str, dict] = {}
        # Popularity from the history-only "seen" sets (home country plus any
        # travel acquired during history), snapshotted now -- before any
        # test-period login (below) mutates them -- so it describes the
        # population the model actually trained on, not one extra day beyond it.
        common_country_popularity = sum(1 for u in normal_users if common_country in profiles[u]["seen"])

        for user in normal_users:
            records, meta = lg.normal_login_records(factory, rng, profiles[user], user, test_day)
            test_records += records
            injection_meta[user] = meta
            diagnostic_features[user] = lg.account_login_features(meta["hour"], meta["is_new_geo"])

        for name in LOGIN_ATTACKS:
            if name == LOGIN_GUARD_CASE:
                continue
            user = attack_users[name]
            record, meta = lg.overlap_attack_record(factory, rng, name, user, test_day, home_country=attacker_home[user])
            test_records.append(record)
            diagnostic_features[user] = lg.account_login_features(meta["hour"], meta["is_new_geo"])

        # Guard case: a country that's new for this attacker account but common
        # across the normal population -- there is no org-wide country-rarity
        # feature, so this is caught via is_new_geo alone today, regardless of
        # the country's popularity. A regression guard (see synthetic_login.py),
        # not a demonstrated blind spot.
        record, meta = lg.guard_case_record(factory, rng, guard_user, test_day, common_country=common_country)
        test_records.append(record)
        diagnostic_features[guard_user] = lg.account_login_features(meta["hour"], meta["is_new_geo"])

        rule.analyze(test_records, db)
        latest = scenario.latest_scores()

        return ScenarioResult(
            key="login",
            seed=seed,
            shipped_threshold=SPECS["login"].shipped_threshold(),
            normal={u: latest[u] for u in normal_users},
            attacks={name: latest[attack_users[name]] for name in LOGIN_ATTACKS},
            meta={
                "population": population,
                "common_country_popularity": common_country_popularity,
                "injection_meta": injection_meta,
                "features": diagnostic_features,
                "attack_ids": attack_users,
            },
        )


# -------------------------------------------------------------- egress

EGRESS_ATTACKS = (
    "volume_loud", "volume_subtle", "spread_loud", "spread_subtle",
    "offhour_loud", "offhour_subtle", "popular_dest_exfil",
)
EGRESS_GUARD_CASE = "popular_dest_exfil"


def run_egress_scenario(
    db: Session, *, seed: int, n_normal: int = 100, history_days: int = 10, population: str = "v2",
) -> ScenarioResult:
    """One seeded scenario: n_normal hosts with their own hourly egress history, plus
    7 attack hosts (3 loud/subtle pairs + 1 popular-destination guard case).

    Same shape as run_threat_log_scenario. Mirrors synthetic_egress.py's overlap
    design. day_offset (not just hour) distinguishes buckets so repeated
    weighted-random hours across history rounds for the same host don't collide
    into a single merged bucket (see synthetic_egress.py's module docstring).
    """

    if population != "v2":
        raise ValueError(f"egress only has population 'v2', got {population!r}")
    label = f"s{seed}"
    with isolated_scenario(db, "egress", label=label) as scenario:
        factory = eg.RecordFactory()
        rng = random.Random(seed * 1000 + 7)
        rare_pool = eg.RarePool()
        # Attacker hosts live in a different third octet from normal hosts
        # (".9." vs. ".0.") so there is no ID collision regardless of n_normal
        # -- unlike a fixed ".100+j" offset, which only avoided colliding with
        # the default n_normal=100 by coincidence.
        host_base = f"10.{60 + seed}.0"
        attack_host_base = f"10.{60 + seed}.9"
        normal_hosts = [f"{host_base}.{i}" for i in range(1, n_normal + 1)]
        attack_hosts = {name: f"{attack_host_base}.{j}" for j, name in enumerate(EGRESS_ATTACKS, start=1)}
        profiles = {h: eg.make_profile(rng) for h in normal_hosts}
        attacker_profiles = {h: eg.make_profile(rng) for h in attack_hosts.values()}

        rule = scenario.rule()

        history: list = []
        for day in range(history_days):
            for host in normal_hosts:
                records, _meta = eg.normal_bucket(factory, rng, rare_pool, profiles[host], host, day)
                history += records
        rule.analyze(history, db)
        assert scenario.snapshot_count() >= SPECS["egress"].min_samples, (
            f"only {scenario.snapshot_count()} egress snapshots, need >= {SPECS['egress'].min_samples} to train"
        )
        scenario.train()

        # Guard-case destination and its popularity, snapshotted from the
        # history-only "seen" sets -- before any test-period bucket (below)
        # mutates them -- so it describes the population the model actually
        # trained on, not one extra day beyond it.
        popular_dest = max(
            eg.POPULAR_POOL, key=lambda d: sum(1 for h in normal_hosts if d in profiles[h]["seen"]),
        )
        popular_dest_popularity = sum(1 for h in normal_hosts if popular_dest in profiles[h]["seen"])

        test_day = history_days  # one calendar day after the history window
        test_records: list = []
        injection_meta: dict[str, dict] = {}
        diagnostic_features: dict[str, dict] = {}
        for host in normal_hosts:
            records, meta = eg.normal_bucket(factory, rng, rare_pool, profiles[host], host, test_day)
            test_records += records
            injection_meta[host] = meta
            diagnostic_features[host] = eg.host_egress_features(records)

        for name in EGRESS_ATTACKS:
            if name == EGRESS_GUARD_CASE:
                continue
            host = attack_hosts[name]
            records, _meta = eg.overlap_attack_records(factory, rng, name, host, test_day, core=attacker_profiles[host]["core"])
            test_records += records
            diagnostic_features[host] = eg.host_egress_features(records)

        # Guard case: a large transfer to a destination common across the other
        # hosts' core sets -- there is no org-wide destination-rarity feature, so
        # this is caught via volume alone today, regardless of the destination's
        # popularity. A regression guard (see synthetic_egress.py), not a
        # demonstrated blind spot.
        guard_host = attack_hosts[EGRESS_GUARD_CASE]
        records, _meta = eg.guard_case_records(factory, rng, guard_host, test_day, popular_dest=popular_dest)
        test_records += records
        diagnostic_features[guard_host] = eg.host_egress_features(records)

        rule.analyze(test_records, db)
        latest = scenario.latest_scores()

        return ScenarioResult(
            key="egress",
            seed=seed,
            shipped_threshold=SPECS["egress"].shipped_threshold(),
            normal={h: latest[h] for h in normal_hosts},
            attacks={name: latest[attack_hosts[name]] for name in EGRESS_ATTACKS},
            meta={
                "population": population,
                "popular_dest_popularity": popular_dest_popularity,
                "injection_meta": injection_meta,
                "features": diagnostic_features,
                "attack_ids": attack_hosts,
            },
        )
