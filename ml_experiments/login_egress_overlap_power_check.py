"""
High-power study for the login_behavior and egress_volume IsolationForest
pilots, mirroring ml_experiments/threat_log_false_positive_power_check.py's
shape and safety properties.

The fast pytest tier (backend/tests/anomaly_eval/test_login_egress_overlap.py)
uses 100 normal accounts/hosts x 5 seeds -- enough to catch a gross failure
but too little data to trust an exact rate. This script reruns both
scenarios at 100 normal entities x 10 seeds (1000 normal-entity observations
per feature set) by calling the real production functions directly --
BehavioralAnomalyLoginRule.analyze() / BehavioralAnomalyEgressRule.analyze(),
the real feature extractors, app.ml.pipeline, train_login_behavior.train() /
train_egress_volume.train() -- the same code a real upload exercises.

Database safety: identical to threat_log_false_positive_power_check.py --
one session against whatever app.core.config.settings.database_url points
to, NEVER commits. Each scenario runs inside a savepoint that is rolled back
when it ends (see backend/tests/anomaly_eval/harness.py), so scenarios
cannot see each other's snapshots, models, or baselines, and a final
db.rollback() discards everything else.

Honest threshold tuning (S7-01.3): thresholds are selected on a TRAIN half
of the seeds (0-4) and validated on a held-out TEST half (5-9) that never
informed the selection -- not tuned in-sample against the same seeds the
report's headline numbers use.

Run:
    backend/.venv/Scripts/python.exe ml_experiments/login_egress_overlap_power_check.py
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
from tests.anomaly_eval.metrics import environment_versions, wilson_ci  # noqa: E402
from tests.anomaly_eval.scenarios import (  # noqa: E402
    EGRESS_GUARD_CASE,
    LOGIN_GUARD_CASE,
    run_egress_scenario,
    run_login_scenario,
)
from tests.anomaly_eval import synthetic_login as lg  # noqa: E402

SEEDS = tuple(range(10))
TRAIN_SEEDS = SEEDS[:5]
TEST_SEEDS = SEEDS[5:]
N_NORMAL = 100
THRESHOLDS = (-0.02, -0.05, -0.08, -0.10, -0.12, -0.15, -0.18)
SHIPPED_THRESHOLD = -0.02
FP_TARGET = 0.02  # the "low-FP" target the honest tuning step checks against
REPORT_FILE = "login_egress_overlap_powered.txt"

LOGIN_HIDDEN_FEATURES = ("hour", "is_new_geo")
EGRESS_HIDDEN_FEATURES = ("bytes_total", "connection_count", "distinct_destinations", "hour")


def login_cause_of(meta: dict) -> str:
    if meta["is_new_geo"]:
        return "new_geo_travel"
    if meta["hour"] not in lg.COMMON_HOURS:
        return "unusual_hour"
    return "no_obvious_cause"


def egress_cause_of(meta: dict) -> str:
    causes = []
    if meta["had_novel_dest"]:
        causes.append("novel_destination")
    if meta["had_spike"]:
        causes.append("volume_spike")
    if not causes:
        return "no_obvious_cause"
    return "+".join(causes)


KINDS = {
    "login": {
        "runner": run_login_scenario,
        "guard": LOGIN_GUARD_CASE,
        "hidden_features": LOGIN_HIDDEN_FEATURES,
        "cause_of": login_cause_of,
    },
    "egress": {
        "runner": run_egress_scenario,
        "guard": EGRESS_GUARD_CASE,
        "hidden_features": EGRESS_HIDDEN_FEATURES,
        "cause_of": egress_cause_of,
    },
}


def run_once(db, runner, *, seed: int) -> dict:
    result = runner(db, seed=seed, n_normal=N_NORMAL)
    return {
        "seed": seed,
        "features": result.meta["features"],
        "attack_ids": result.meta["attack_ids"],
        "normal_scores": result.normal,
        "loud_scores": result.attacks_where("_loud"),
        "subtle_scores": result.attacks_where("_subtle"),
        "attack_scores": result.attacks,  # by name, includes the guard case
        "guard_popularity": result.meta.get("common_country_popularity", result.meta.get("popular_dest_popularity")),
        "injection_meta": result.meta["injection_meta"],
        "shipped_threshold": result.shipped_threshold,
    }


def run_kind(kind: str) -> list[dict]:
    spec = KINDS[kind]
    db = SessionLocal()
    results = []
    try:
        for seed in SEEDS:
            results.append(run_once(db, spec["runner"], seed=seed))
            print(f"[{kind}] done: seed={seed}")
    finally:
        db.rollback()
        db.close()
    return results


def _pooled_scores(results: list[dict], seeds: tuple[int, ...]):
    subset = [r for r in results if r["seed"] in seeds]
    normal = [s for r in subset for s in r["normal_scores"].values()]
    loud = [s for r in subset for s in r["loud_scores"].values()]
    subtle = [s for r in subset for s in r["subtle_scores"].values()]
    return normal, loud, subtle


def single_feature_section(results: list[dict], guard: str, hidden_features: tuple[str, ...]) -> list[str]:
    lines = ["--- single-feature separability (diagnostic, not the model) ---",
             "AUC oriented so 0.5 = chance, 1.0 = perfectly separable; 'direction' is which way attacks differ"]
    for feature in hidden_features:
        labels, values = [], []
        for run in results:
            attack_ids = {ent for name, ent in run["attack_ids"].items() if name != guard}
            for ent, feats in run["features"].items():
                labels.append(1 if ent in attack_ids else 0)
                values.append(float(feats[feature]))
        raw_auc = roc_auc_score(labels, values)
        direction = "attacks higher" if raw_auc > 0.5 else "attacks lower"
        lines.append(f"{feature:>22}: AUC {max(raw_auc, 1 - raw_auc):.4f}  ({direction})")
    lines.append("")
    return lines


def threshold_sweep_section(normal: list[float], loud: list[float], subtle: list[float], label: str) -> list[str]:
    lines = [f"--- threshold sensitivity ({label}) ---"]
    header = f"{'threshold':>10} {'fp_rate':>9} {'loud_detect':>12} {'loud_95ci':>20} {'subtle_detect':>14} {'subtle_95ci':>20}"
    lines.append(header)
    for t in THRESHOLDS:
        fp_rate = sum(1 for s in normal if s < t) / len(normal)
        loud_hits = sum(1 for s in loud if s < t)
        subtle_hits = sum(1 for s in subtle if s < t)
        loud_rate = loud_hits / len(loud)
        subtle_rate = subtle_hits / len(subtle)
        loud_low, loud_high = wilson_ci(loud_hits, len(loud))
        subtle_low, subtle_high = wilson_ci(subtle_hits, len(subtle))
        lines.append(f"{t:>10} {fp_rate:>9.2%} {loud_rate:>12.1%} "
                      f"{f'[{loud_low:.1%}, {loud_high:.1%}]':>20} {subtle_rate:>14.1%} "
                      f"{f'[{subtle_low:.1%}, {subtle_high:.1%}]':>20}")
    lines.append("")
    return lines


def held_out_threshold_check(results: list[dict]) -> list[str]:
    """S7-01.3: pick a threshold from TRAIN_SEEDS only (closest to FP_TARGET
    without exceeding it), then report that FIXED threshold's FP/detection on
    TEST_SEEDS only -- seeds that never informed the choice."""

    train_normal, train_loud, train_subtle = _pooled_scores(results, TRAIN_SEEDS)
    test_normal, test_loud, test_subtle = _pooled_scores(results, TEST_SEEDS)

    candidates = []
    for t in THRESHOLDS:
        fp_rate = sum(1 for s in train_normal if s < t) / len(train_normal)
        candidates.append((t, fp_rate))
    under_target = [c for c in candidates if c[1] <= FP_TARGET]
    chosen = max(under_target, key=lambda c: c[0]) if under_target else min(candidates, key=lambda c: c[1])
    chosen_threshold, train_fp_rate = chosen

    lines = [f"--- honest threshold tuning: selected on seeds {TRAIN_SEEDS}, validated on held-out seeds {TEST_SEEDS} ---"]
    if not under_target:
        lines.append(
            f"FINDING: no swept threshold reaches the {FP_TARGET:.0%} FP target on the train half "
            f"(best achievable: {train_fp_rate:.2%} at {chosen_threshold}). This is a limit of the "
            "5-feature model on this synthetic population, not a tuning failure -- reported as-is."
        )
    lines.append(f"candidate threshold (train-half FP {train_fp_rate:.2%}): {chosen_threshold}")

    test_fp = sum(1 for s in test_normal if s < chosen_threshold)
    test_fp_rate = test_fp / len(test_normal)
    fp_low, fp_high = wilson_ci(test_fp, len(test_normal))
    test_loud_hits = sum(1 for s in test_loud if s < chosen_threshold)
    test_subtle_hits = sum(1 for s in test_subtle if s < chosen_threshold)
    loud_low, loud_high = wilson_ci(test_loud_hits, len(test_loud))
    subtle_low, subtle_high = wilson_ci(test_subtle_hits, len(test_subtle))
    lines.append(
        f"held-out FP @ {chosen_threshold}: {test_fp_rate:.2%} ({test_fp}/{len(test_normal)}) "
        f"95% CI [{fp_low:.2%}, {fp_high:.2%}]"
    )
    lines.append(
        f"held-out loud detection @ {chosen_threshold}: {test_loud_hits}/{len(test_loud)} "
        f"= {test_loud_hits/len(test_loud):.1%} 95% CI [{loud_low:.1%}, {loud_high:.1%}]"
    )
    lines.append(
        f"held-out subtle detection @ {chosen_threshold}: {test_subtle_hits}/{len(test_subtle)} "
        f"= {test_subtle_hits/len(test_subtle):.1%} 95% CI [{subtle_low:.1%}, {subtle_high:.1%}]"
    )
    lines.append(
        "Not changing the shipped DEFAULT_PARAMS['score_threshold'] as part of this eval -- both rules "
        "ship shadow_mode=True, so the threshold has no live effect today; flipping it is a separate "
        "product decision. This documents what threshold would be needed and its cost."
    )
    lines.append("")
    return lines


def build_section(kind: str, results: list[dict]) -> str:
    spec = KINDS[kind]
    guard = spec["guard"]
    lines = []
    feature_set_name = "login_behavior" if kind == "login" else "egress_volume"
    lines.append(f"Powered overlap check for {feature_set_name}")
    lines.append("=" * 88)
    lines.append(f"{N_NORMAL} normal entities x {len(SEEDS)} seeds ({N_NORMAL * len(SEEDS)} observations)")
    lines.append(f"shipped threshold: {SHIPPED_THRESHOLD}")
    lines.append("detection/FP rates are shown with 95% Wilson CIs. Population is v2 (overlapping) only -- see the")
    lines.append("anomaly_eval README for the overlap design and what each loud/subtle attack departs on.")
    lines.append("")

    all_normal, all_loud, all_subtle = _pooled_scores(results, SEEDS)

    fp_count = sum(1 for s in all_normal if s < SHIPPED_THRESHOLD)
    fp_rate = fp_count / len(all_normal)
    ci_low, ci_high = wilson_ci(fp_count, len(all_normal))
    per_seed_fp_rates = [
        sum(1 for s in r["normal_scores"].values() if s < SHIPPED_THRESHOLD) / len(r["normal_scores"])
        for r in results
    ]
    loud_hits = sum(1 for s in all_loud if s < SHIPPED_THRESHOLD)
    subtle_hits = sum(1 for s in all_subtle if s < SHIPPED_THRESHOLD)
    loud_low, loud_high = wilson_ci(loud_hits, len(all_loud))
    subtle_low, subtle_high = wilson_ci(subtle_hits, len(all_subtle))

    cause_tally = Counter()
    for r in results:
        for ent, score in r["normal_scores"].items():
            if score < SHIPPED_THRESHOLD:
                cause_tally[spec["cause_of"](r["injection_meta"][ent])] += 1

    auc_labels = [0] * len(all_normal) + [1] * (len(all_loud) + len(all_subtle))
    auc_scores = [-s for s in all_normal] + [-s for s in all_loud] + [-s for s in all_subtle]
    auc = roc_auc_score(auc_labels, auc_scores)

    lines.append(f"pooled FP rate @ {SHIPPED_THRESHOLD}: {fp_rate:.2%} ({fp_count}/{len(all_normal)})  "
                  f"95% Wilson CI: [{ci_low:.2%}, {ci_high:.2%}]")
    lines.append(f"FP rate spread across {len(SEEDS)} seeds: "
                  f"min={min(per_seed_fp_rates):.1%} max={max(per_seed_fp_rates):.1%} "
                  f"mean={statistics.mean(per_seed_fp_rates):.1%} stdev={statistics.pstdev(per_seed_fp_rates):.1%}")
    lines.append(f"loud-attack detection rate @ {SHIPPED_THRESHOLD}:   {loud_hits}/{len(all_loud)} = "
                  f"{loud_hits/len(all_loud):.1%}  95% Wilson CI: [{loud_low:.2%}, {loud_high:.2%}]")
    lines.append(f"subtle-attack detection rate @ {SHIPPED_THRESHOLD}: {subtle_hits}/{len(all_subtle)} = "
                  f"{subtle_hits/len(all_subtle):.1%}  95% Wilson CI: [{subtle_low:.2%}, {subtle_high:.2%}]")
    lines.append(f"ROC-AUC (loud+subtle vs. all normals): {auc:.4f}")
    lines.append(f"false-positive causes (n={fp_count}): {dict(cause_tally) if fp_count else 'n/a'}")
    lines.append("")

    lines += threshold_sweep_section(all_normal, all_loud, all_subtle, "pooled across all 10 seeds")
    lines += held_out_threshold_check(results)

    # --- guard case: documents the missing org-wide rarity feature ---
    lines.append(f"--- guard case: {guard} ---")
    guard_scores = [r["attack_scores"][guard] for r in results]
    guard_popularity = [r["guard_popularity"] for r in results]
    guard_flagged = sum(1 for s in guard_scores if s < SHIPPED_THRESHOLD)
    lines.append(
        f"score min={min(guard_scores):.4f} max={max(guard_scores):.4f} mean={statistics.mean(guard_scores):.4f}  |  "
        f"flagged @ {SHIPPED_THRESHOLD}: {guard_flagged}/{len(guard_scores)}  |  "
        f"popularity among {N_NORMAL} normals: min={min(guard_popularity)} max={max(guard_popularity)} "
        f"mean={statistics.mean(guard_popularity):.1f}"
    )
    lines.append(
        "Under the current per-entity-only features, this scores like any other first-sighting "
        "event -- global popularity has no effect yet. This is the baseline a future org-wide-"
        "rarity feature must not erase: re-run this script after that change and confirm this "
        "number stays comparably negative."
    )
    lines.append("")

    lines += single_feature_section(results, guard, spec["hidden_features"])
    return "\n".join(lines)


def main() -> int:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    versions = environment_versions()
    sections = ["library versions: " + "  ".join(f"{name}={version}" for name, version in sorted(versions.items()))]
    for kind in ("login", "egress"):
        results = run_kind(kind)
        section = build_section(kind, results)
        print("\n" + section)
        sections.append(section)
    report = "\n\n".join(sections) + "\n"
    (REPORTS_DIR / REPORT_FILE).write_text(report, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
