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
not a disposable test database) and NEVER commits. Each scenario also runs
inside a savepoint that is rolled back when it ends (see
backend/tests/anomaly_eval/harness.py), so scenarios cannot see each other's
snapshots, models or per-IP history, and a final db.rollback() discards
everything else. No cleanup step is needed and no real data is ever touched.

Run:
    backend/.venv/Scripts/python.exe ml_experiments/threat_log_false_positive_power_check.py
"""

from __future__ import annotations

import statistics
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BACKEND = ROOT.parent / "backend"
REPORTS_DIR = ROOT / "reports"
sys.path.insert(0, str(BACKEND))

from sklearn.metrics import roc_auc_score  # noqa: E402

from app.db.session import SessionLocal  # noqa: E402
from tests.anomaly_eval.metrics import wilson_ci  # noqa: E402
from tests.anomaly_eval.scenarios import run_threat_log_scenario  # noqa: E402

NOVELTY_LEVELS = (0.0, 0.05, 0.15, 0.30)
SEEDS = tuple(range(10))
N_NORMAL = 100
THRESHOLDS = (-0.10, -0.12, -0.15, -0.18)
CURRENT_THRESHOLD = -0.12
MARGIN_BAND = 0.05  # "within 0.05 of the threshold"


def run_once(db, *, novelty_level: float, seed: int, level_idx: int) -> dict:
    """One (novelty_level, seed) scenario: 100 normal IPs + 7 attack IPs
    (3 loud, 3 subtle, 1 exfil-to-popular-destination guard case).

    The generators, the per-scenario FEATURE_SET isolation and the savepoint
    rollback now live in backend/tests/anomaly_eval (shared with the login and
    egress evals). Scores were verified bit-identical to this script's previous
    in-file implementation (8 scenarios, 856 scores) before the swap.
    """

    result = run_threat_log_scenario(db, novelty_level=novelty_level, seed=seed, level_idx=level_idx, n_normal=N_NORMAL)
    return {
        "novelty_level": novelty_level,
        "seed": seed,
        "normal_scores": result.normal,
        "loud_scores": result.attacks_where("_loud"),
        "subtle_scores": result.attacks_where("_subtle"),
        "exfil_score": result.attacks["exfil_popular"],
        "exfil_dest_popularity": result.meta["exfil_dest_popularity"],  # how many of the 100 normal IPs had already used this destination
        "injection_meta": result.meta["injection_meta"],
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
