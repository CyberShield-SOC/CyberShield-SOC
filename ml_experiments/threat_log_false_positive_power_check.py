"""
High-power follow-up to backend/tests/test_ml_threat_log_false_positive_check.py.

That pytest version uses 30 normal IPs x 1 seed per novelty level -- enough
to catch a gross failure but too little data to trust an exact false-
positive rate (a 1/30 FP has a huge confidence interval). This script reruns
the same scenario at 100 normal IPs x 10 seeds per novelty level (4000
normal-IP observations total) by calling the real production functions
directly -- BehavioralAnomalyThreatLogRule.analyze(), features_threat_log,
app.ml.pipeline, train_threat_detection.train() -- the same code a real
upload exercises, just without the HTTP/CSV-parsing layer (30x more IPs x
10x more seeds x going through /upload would be slow for no benefit: the
upload endpoint and CSV parser aren't what's being measured here).

Lives in ml_experiments/, not backend/tests/, because it's a measurement
run, not a regression test with pass/fail assertions -- same reasoning as
eval_production_threat_log_features.py.

Database safety: this opens one session against whatever
app.core.config.settings.database_url points to (the normal dev database,
not a disposable test database) and NEVER commits -- every write in this
codebase's repositories flushes but does not commit (confirmed against
app/repositories/ml_repository.py and baseline_repository.py), so every
row this script creates is visible to its own later queries within the one
open transaction, and a final db.rollback() discards all of it. No cleanup
step is needed and no real data is ever touched.

Run:
    backend/.venv/Scripts/python.exe ml_experiments/threat_log_false_positive_power_check.py
"""

from __future__ import annotations

import itertools
import random
import statistics
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BACKEND = ROOT.parent / "backend"
REPORTS_DIR = ROOT / "reports"
sys.path.insert(0, str(BACKEND))

from sklearn.metrics import roc_auc_score  # noqa: E402

import app.detection.rules.behavioral_anomaly_threat_log as rule_module  # noqa: E402
import app.ml.train_threat_detection as train_module  # noqa: E402
from app.db.session import SessionLocal  # noqa: E402
from app.detection.models import LogRecord  # noqa: E402
from app.repositories.ml_repository import list_feature_snapshots  # noqa: E402

BASE = datetime(2026, 1, 5, tzinfo=timezone.utc)
NORMAL_PORTS = {443: "HTTPS", 80: "HTTP"}
CORE_POOL = [f"198.51.100.{i}" for i in range(10, 30)]
POPULAR_POOL = [f"192.0.2.{i}" for i in range(10, 20)]
SPIKE_PROB = 0.08
DENY_RATE_RANGE = (0.05, 0.20)

NOVELTY_LEVELS = (0.0, 0.05, 0.15, 0.30)
SEEDS = tuple(range(10))
N_NORMAL = 100
THRESHOLDS = (-0.10, -0.12, -0.15, -0.18)
CURRENT_THRESHOLD = -0.12
MARGIN_BAND = 0.05  # "within 0.05 of the threshold"

_line_counter = itertools.count(1)


def _ts(hour: int, minute: int, second: int = 0) -> str:
    return BASE.replace(hour=hour, minute=minute, second=second).strftime("%Y-%m-%dT%H:%M:%SZ")


def mk(ts_str: str, source_ip: str, dest_ip: str, protocol: str, port: int, bytes_out: int, status: str) -> LogRecord:
    return LogRecord(
        line_number=next(_line_counter), timestamp=ts_str, ip_address=source_ip, dest_ip=dest_ip,
        protocol=protocol, port=port, bytes_out=bytes_out, status=status,
    )


class RarePool:
    """True long-tail destinations, disjoint from CORE_POOL/POPULAR_POOL and
    from every attack generator's fixed destinations (203.0.113.x)."""

    def __init__(self):
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
    rng: random.Random, rare_pool: RarePool, profile: dict, source_ip: str, hour: int, novelty_level: float,
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
        records.append(mk(
            _ts(hour, minute=rng.randint(0, 59), second=i), source_ip, dest,
            NORMAL_PORTS[port], port, rng.randint(2_000, 20_000), status,
        ))

    had_spike = rng.random() < SPIKE_PROB
    if had_spike:
        spike_dest = rng.choice(profile["core"] + POPULAR_POOL)
        records.append(mk(
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


def port_scan_records(source_ip: str, hour: int, *, dest: str, num_ports: int) -> list[LogRecord]:
    return [
        mk(_ts(hour, minute=i % 60), source_ip, dest, "TCP", 20_000 + i, 100, "ALLOWED")
        for i in range(num_ports)
    ]


def big_transfer_records(source_ip: str, hour: int, *, dest: str, bytes_out: int, count: int) -> list[LogRecord]:
    return [
        mk(_ts(hour, minute=5 * i), source_ip, dest, "HTTPS", 443, bytes_out, "ALLOWED")
        for i in range(count)
    ]


def deny_burst_records(source_ip: str, hour: int, *, dest: str, count: int, deny_fraction: float) -> list[LogRecord]:
    denied_count = round(count * deny_fraction)
    return [
        mk(_ts(hour, minute=i % 60), source_ip, dest, "HTTPS", 443, 500, "DENIED" if i < denied_count else "ALLOWED")
        for i in range(count)
    ]


def wilson_ci(successes: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (0.0, 0.0)
    phat = successes / n
    denom = 1 + z**2 / n
    centre = phat + z**2 / (2 * n)
    margin = z * ((phat * (1 - phat) / n + z**2 / (4 * n**2)) ** 0.5)
    return (max(0.0, (centre - margin) / denom), min(1.0, (centre + margin) / denom))


def run_once(db, *, novelty_level: float, seed: int, level_idx: int) -> dict:
    """One (novelty_level, seed) scenario: 100 normal IPs + 7 attack IPs
    (3 loud, 3 subtle, 1 exfil-to-popular-destination guard case), via the
    real rule/pipeline/training functions directly."""

    feature_set = f"fpcheck-{int(novelty_level * 100)}-{seed}"
    rule_module.FEATURE_SET = feature_set
    train_module.FEATURE_SET = feature_set

    rng = random.Random(seed * 1000 + level_idx)
    rare_pool = RarePool()
    ip_base = f"10.{200 + level_idx}.{seed}"
    normal_ips = [f"{ip_base}.{i}" for i in range(1, N_NORMAL + 1)]
    attack_names = [
        "port_scan_loud", "big_transfer_loud", "deny_burst_loud",
        "port_scan_subtle", "big_transfer_subtle", "deny_burst_subtle",
        "exfil_popular",
    ]
    attack_ips = {name: f"{ip_base}.{100 + j}" for j, name in enumerate(attack_names, start=1)}
    all_ips = normal_ips + list(attack_ips.values())
    profiles = {ip: make_profile(rng) for ip in all_ips}

    rule = rule_module.BehavioralAnomalyThreatLogRule()

    history_records: list[LogRecord] = []
    for hour in range(6):
        for ip in all_ips:
            recs, _meta = realistic_bucket_records(rng, rare_pool, profiles[ip], ip, hour, novelty_level)
            history_records += recs
    rule.analyze(history_records, db)

    snapshot_count = len(list_feature_snapshots(db, feature_set=feature_set, entity_type="source_ip"))
    assert snapshot_count >= 50, f"only {snapshot_count} snapshots for {feature_set}"

    model_row = train_module.train(db, min_samples=50, random_state=42)
    db.flush()
    assert model_row.is_active

    test_records: list[LogRecord] = []
    injection_meta: dict[str, dict] = {}
    for ip in normal_ips:
        recs, meta = realistic_bucket_records(rng, rare_pool, profiles[ip], ip, hour=6, novelty_level=novelty_level)
        test_records += recs
        injection_meta[ip] = meta

    test_records += port_scan_records(attack_ips["port_scan_loud"], hour=6, dest=CORE_POOL[0], num_ports=25)
    test_records += big_transfer_records(
        attack_ips["big_transfer_loud"], hour=6, dest="203.0.113.77", bytes_out=800_000_000, count=2,
    )
    test_records += deny_burst_records(
        attack_ips["deny_burst_loud"], hour=6, dest=CORE_POOL[0], count=20, deny_fraction=1.0,
    )
    test_records += port_scan_records(attack_ips["port_scan_subtle"], hour=6, dest=CORE_POOL[1], num_ports=5)
    test_records += big_transfer_records(
        attack_ips["big_transfer_subtle"], hour=6, dest="203.0.113.88", bytes_out=50_000_000, count=1,
    )
    test_records += deny_burst_records(
        attack_ips["deny_burst_subtle"], hour=6, dest=CORE_POOL[1], count=20, deny_fraction=0.4,
    )

    # Exfil to a destination many normal IPs already use (guard case for a
    # future org-wide rarity feature): pick a POPULAR_POOL entry this
    # specific attacker IP has never visited itself, so per-IP novelty is
    # still genuinely triggered -- what's different from big_transfer_loud
    # is that this destination is *not* rare across the organization.
    exfil_ip = attack_ips["exfil_popular"]
    exfil_dest = next(d for d in POPULAR_POOL if d not in profiles[exfil_ip]["seen"])
    popularity = sum(1 for ip in normal_ips if exfil_dest in profiles[ip]["seen"])
    test_records += big_transfer_records(exfil_ip, hour=6, dest=exfil_dest, bytes_out=500_000_000, count=1)

    rule.analyze(test_records, db)

    all_snapshots = list_feature_snapshots(db, feature_set=feature_set, entity_type="source_ip")
    latest_by_ip = {}
    for snapshot in all_snapshots:
        latest_by_ip[snapshot.entity_id] = snapshot

    normal_scores = {ip: latest_by_ip[ip].score for ip in normal_ips}
    attack_scores = {name: latest_by_ip[ip].score for name, ip in attack_ips.items() if name != "exfil_popular"}
    loud_scores = {k: v for k, v in attack_scores.items() if k.endswith("_loud")}
    subtle_scores = {k: v for k, v in attack_scores.items() if k.endswith("_subtle")}
    exfil_score = latest_by_ip[exfil_ip].score

    return {
        "novelty_level": novelty_level,
        "seed": seed,
        "normal_scores": normal_scores,
        "loud_scores": loud_scores,
        "subtle_scores": subtle_scores,
        "exfil_score": exfil_score,
        "exfil_dest_popularity": popularity,  # how many of the 100 normal IPs had already used this destination
        "injection_meta": injection_meta,
    }


def cause_of(meta: dict) -> str:
    causes = []
    if meta["had_novel_dest"]:
        causes.append("new_destination")
    if meta["had_spike"]:
        causes.append("volume_spike")
    if meta["assigned_deny_rate"] > 0.15:
        causes.append("elevated_deny_rate")
    if not causes:
        return "no_obvious_cause"
    return "+".join(causes) if len(causes) > 1 else causes[0]


def main() -> int:
    db = SessionLocal()
    results_by_level: dict[float, list[dict]] = {level: [] for level in NOVELTY_LEVELS}
    try:
        for level_idx, level in enumerate(NOVELTY_LEVELS):
            for seed in SEEDS:
                results_by_level[level].append(run_once(db, novelty_level=level, seed=seed, level_idx=level_idx))
                print(f"done: novelty={level:.0%} seed={seed}")
    finally:
        db.rollback()
        db.close()

    report = build_report(results_by_level)
    print("\n" + report)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    (REPORTS_DIR / "threat_log_false_positive_powered.txt").write_text(report, encoding="utf-8")
    return 0


def build_report(results_by_level: dict[float, list[dict]]) -> str:
    lines = []
    lines.append("Powered false-positive check for behavioral_anomaly_threat_log")
    lines.append("=" * 88)
    lines.append(f"{N_NORMAL} normal IPs x {len(SEEDS)} seeds per novelty level ({N_NORMAL * len(SEEDS)} observations/level)")
    lines.append(f"current provisional threshold: {CURRENT_THRESHOLD}")
    lines.append("")

    # Collected across everything, for the threshold-sensitivity table and
    # the pooled exfil-to-popular-destination summary.
    all_normal_scores: list[float] = []
    all_loud_scores: list[float] = []
    all_subtle_scores: list[float] = []
    all_exfil_scores: list[tuple[float, int]] = []  # (score, popularity among normals)

    for level in NOVELTY_LEVELS:
        runs = results_by_level[level]
        lines.append(f"--- novelty_level={level:.0%} ({len(runs)} seeds) ---")

        pooled_normal = [s for r in runs for s in r["normal_scores"].values()]
        pooled_loud = [s for r in runs for s in r["loud_scores"].values()]
        pooled_subtle = [s for r in runs for s in r["subtle_scores"].values()]
        all_normal_scores += pooled_normal
        all_loud_scores += pooled_loud
        all_subtle_scores += pooled_subtle
        for r in runs:
            all_exfil_scores.append((r["exfil_score"], r["exfil_dest_popularity"]))

        fp_count = sum(1 for s in pooled_normal if s < CURRENT_THRESHOLD)
        fp_rate = fp_count / len(pooled_normal)
        ci_low, ci_high = wilson_ci(fp_count, len(pooled_normal))
        per_seed_fp_rates = [
            sum(1 for s in r["normal_scores"].values() if s < CURRENT_THRESHOLD) / len(r["normal_scores"])
            for r in runs
        ]

        loud_detect = sum(1 for s in pooled_loud if s < CURRENT_THRESHOLD) / len(pooled_loud)
        subtle_detect = sum(1 for s in pooled_subtle if s < CURRENT_THRESHOLD) / len(pooled_subtle)

        margin_count = sum(1 for s in pooled_normal if abs(s - CURRENT_THRESHOLD) <= MARGIN_BAND)

        cause_tally = Counter()
        for r in runs:
            for ip, score in r["normal_scores"].items():
                if score < CURRENT_THRESHOLD:
                    cause_tally[cause_of(r["injection_meta"][ip])] += 1

        auc_labels = [0] * len(pooled_normal) + [1] * (len(pooled_loud) + len(pooled_subtle))
        auc_scores = [-s for s in pooled_normal] + [-s for s in pooled_loud] + [-s for s in pooled_subtle]
        auc = roc_auc_score(auc_labels, auc_scores)

        lines.append(f"pooled FP rate @ {CURRENT_THRESHOLD}: {fp_rate:.2%} ({fp_count}/{len(pooled_normal)})  "
                      f"95% Wilson CI: [{ci_low:.2%}, {ci_high:.2%}]")
        lines.append(f"FP rate spread across {len(SEEDS)} seeds: "
                      f"min={min(per_seed_fp_rates):.1%} max={max(per_seed_fp_rates):.1%} "
                      f"mean={statistics.mean(per_seed_fp_rates):.1%} stdev={statistics.pstdev(per_seed_fp_rates):.1%}")
        lines.append(f"per-seed FP rates: {[f'{r:.0%}' for r in per_seed_fp_rates]}")
        lines.append(f"normal IPs within {MARGIN_BAND} of threshold: {margin_count}/{len(pooled_normal)} "
                      f"({margin_count / len(pooled_normal):.2%})")
        lines.append(f"loud-attack detection rate @ {CURRENT_THRESHOLD}:   {loud_detect:.1%} ({len(pooled_loud)} instances)")
        lines.append(f"subtle-attack detection rate @ {CURRENT_THRESHOLD}: {subtle_detect:.1%} ({len(pooled_subtle)} instances)")
        lines.append(f"ROC-AUC (loud+subtle vs. all normals): {auc:.4f}")
        lines.append(f"false-positive causes (n={fp_count}): {dict(cause_tally) if fp_count else 'n/a'}")
        lines.append("")

    # --- Threshold sensitivity, pooled across all levels+seeds ---
    lines.append("--- threshold sensitivity (pooled across all novelty levels and seeds) ---")
    header = f"{'threshold':>10} {'fp_rate':>9} {'loud_detect':>12} {'subtle_detect':>14}"
    lines.append(header)
    for t in THRESHOLDS:
        fp_rate = sum(1 for s in all_normal_scores if s < t) / len(all_normal_scores)
        loud_rate = sum(1 for s in all_loud_scores if s < t) / len(all_loud_scores)
        subtle_rate = sum(1 for s in all_subtle_scores if s < t) / len(all_subtle_scores)
        lines.append(f"{t:>10} {fp_rate:>9.2%} {loud_rate:>12.1%} {subtle_rate:>14.1%}")
    lines.append("")

    # --- Exfil-to-popular-destination guard case ---
    lines.append("--- exfil to a popular destination (guard case for a future org-rarity feature) ---")
    lines.append(
        "Note: at novelty_level=0%, normal IPs never visit POPULAR_POOL at all by construction "
        "(novelty is off), so the chosen destination has 0 real popularity in that case -- "
        "popularity only becomes genuine at the higher novelty levels, so this is broken out "
        "per level rather than pooled."
    )
    for level in NOVELTY_LEVELS:
        level_pairs = [(r["exfil_score"], r["exfil_dest_popularity"]) for r in results_by_level[level]]
        scores_only = [s for s, _p in level_pairs]
        popularity_vals = [p for _s, p in level_pairs]
        flagged = sum(1 for s in scores_only if s < CURRENT_THRESHOLD)
        lines.append(
            f"novelty={level:.0%}: score min={min(scores_only):.4f} max={max(scores_only):.4f} "
            f"mean={statistics.mean(scores_only):.4f}  |  flagged @ {CURRENT_THRESHOLD}: "
            f"{flagged}/{len(scores_only)}  |  destination popularity among 100 normals: "
            f"min={min(popularity_vals)} max={max(popularity_vals)} mean={statistics.mean(popularity_vals):.1f}"
        )
    all_scores_only = [s for s, _p in all_exfil_scores]
    all_flagged = sum(1 for s in all_scores_only if s < CURRENT_THRESHOLD)
    lines.append(
        f"pooled across all levels: flagged @ {CURRENT_THRESHOLD}: {all_flagged}/{len(all_scores_only)} "
        f"({all_flagged / len(all_scores_only):.1%})"
    )
    lines.append(
        "Under the CURRENT per-IP-only features, this scores like any other first-visit "
        "large transfer -- global popularity has no effect yet. This is the baseline a "
        "future org-wide-rarity feature (Fix 1) must not erase: re-run this script after "
        "that change and confirm this number stays comparably negative."
    )

    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    raise SystemExit(main())
