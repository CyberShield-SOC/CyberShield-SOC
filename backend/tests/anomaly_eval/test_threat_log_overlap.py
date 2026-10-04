"""Bands for the v2 (overlapping) threat-log synthetic population.

These assert what the overlap is supposed to produce, not that the detector is
good. The v1 population (separable by construction) is covered by
tests/test_ml_threat_log_attack_injection.py and is deliberately left unchanged.

What is asserted, pooled over five seeded scenarios at the 5% novelty level:

- false-positive rate on normal IPs at the shipped threshold is at most ~1%;
- the single features that the overlap was built to hide (record count,
  distinct destinations, distinct ports, deny rate) are near chance;
- bytes total keeps its real discriminative power (a floor, not a ceiling),
  so the overlap is not flattening a feature that genuinely separates traffic;
- detection of loud and subtle attacks lies in a realistic band, not near 100%.

Bands are wide on purpose. Exact scores can move across library versions, and
the detection band is a statement about this synthetic population only.
"""

from __future__ import annotations

import pytest
from sklearn.metrics import roc_auc_score

from tests.anomaly_eval.metrics import wilson_ci
from tests.anomaly_eval.scenarios import run_threat_log_scenario

NOVELTY = 0.05
LEVEL_IDX = 1  # same ip_base / rng offset as the 5% level in the powered study
SEEDS = (0, 1, 2, 3, 4)

FP_CEILING = 0.01
CHANCE_BAND = 0.10  # |AUC - 0.5| must be within this for features the overlap hides
BYTES_FLOOR = 0.70  # bytes must stay clearly discriminative
DETECTION_BAND = (0.20, 0.45)
HIDDEN_FEATURES = ("record_count", "distinct_dests", "distinct_ports", "deny_rate")


_CACHED_RESULTS: list | None = None


def _scenario_results(db_session):
    """Run the five scenarios once and reuse them. ScenarioResult holds plain Python
    data, so the cache stays valid after each scenario's savepoint is rolled back."""

    global _CACHED_RESULTS
    if _CACHED_RESULTS is None:
        _CACHED_RESULTS = [
            run_threat_log_scenario(db_session, novelty_level=NOVELTY, seed=seed, level_idx=LEVEL_IDX, population="v2")
            for seed in SEEDS
        ]
    return _CACHED_RESULTS


@pytest.fixture
def pooled(db_session):
    return _scenario_results(db_session)


def _pool(results):
    threshold = results[0].shipped_threshold
    normal_scores, loud_scores, subtle_scores = [], [], []
    labels, feature_rows = [], {name: [] for name in ("record_count", "distinct_dests", "distinct_ports", "bytes_total", "deny_rate")}
    for run in results:
        normal_scores += list(run.normal.values())
        loud_scores += list(run.attacks_where("_loud").values())
        subtle_scores += list(run.attacks_where("_subtle").values())
        attack_ips = {ip for name, ip in run.meta["attack_ips"].items() if not name.startswith("exfil")}
        for ip, feats in run.meta["features"].items():
            labels.append(1 if ip in attack_ips else 0)
            for name in feature_rows:
                feature_rows[name].append(float(feats[name]))
    return threshold, normal_scores, loud_scores, subtle_scores, labels, feature_rows


def test_false_positive_rate_on_normal_ips_is_at_most_about_one_percent(pooled):
    threshold, normal_scores, *_ = _pool(pooled)
    flagged = sum(1 for s in normal_scores if s < threshold)
    rate = flagged / len(normal_scores)
    low, high = wilson_ci(flagged, len(normal_scores))
    assert rate <= FP_CEILING, (
        f"FP {rate:.2%} ({flagged}/{len(normal_scores)}), 95% CI [{low:.2%}, {high:.2%}], "
        f"above the {FP_CEILING:.0%} ceiling"
    )


@pytest.mark.parametrize("feature", HIDDEN_FEATURES)
def test_overlap_hides_single_features_near_chance(pooled, feature):
    _, _, _, _, labels, feature_rows = _pool(pooled)
    auc = roc_auc_score(labels, feature_rows[feature])
    assert abs(auc - 0.5) <= CHANCE_BAND, (
        f"single-feature AUC for {feature} is {auc:.3f}; overlap should leave it within "
        f"{CHANCE_BAND} of chance (0.5)"
    )


def test_bytes_keeps_real_discriminative_power(pooled):
    _, _, _, _, labels, feature_rows = _pool(pooled)
    auc = roc_auc_score(labels, feature_rows["bytes_total"])
    oriented = max(auc, 1 - auc)
    assert oriented >= BYTES_FLOOR, (
        f"bytes_total single-feature AUC is {oriented:.3f}; below the {BYTES_FLOOR} floor, "
        "so the overlap may be flattening a feature that really separates traffic"
    )


@pytest.mark.parametrize("kind", ["loud", "subtle"])
def test_detection_is_in_a_realistic_band_not_near_perfect(pooled, kind):
    threshold, _, loud_scores, subtle_scores, *_ = _pool(pooled)
    scores = loud_scores if kind == "loud" else subtle_scores
    hits = sum(1 for s in scores if s < threshold)
    rate = hits / len(scores)
    low, high = wilson_ci(hits, len(scores))
    band_low, band_high = DETECTION_BAND
    assert band_low <= rate <= band_high, (
        f"{kind} detection {rate:.1%} ({hits}/{len(scores)}), 95% CI [{low:.1%}, {high:.1%}], "
        f"outside the {band_low:.0%}-{band_high:.0%} band"
    )
