"""Bands for the overlapping (v2) login and egress synthetic populations.

Same style as test_threat_log_overlap.py: assert what the overlap is supposed
to produce, not that the detector is good. Pooled over five seeded scenarios
per feature set.

Unlike threat_log (which pools 4 diagnostic features down from a rich bucket
of per-IP summary stats, with bytes_total deliberately kept as a floor
feature), login_behavior and egress_volume have only 5 features each and no
feature was deliberately spared from the overlap -- so CHANCE_BAND is wider
here than threat_log's 0.10, documented per feature set below, and there is
no floor-feature test.

Both FP_BAND and DETECTION_BAND are centered on what the generators actually
produce at the shipped -0.02 threshold (measured directly, not assumed): a
high false-positive rate is the honest finding this eval exists to surface,
not a bug in the test.
"""

from __future__ import annotations

import pytest
from sklearn.metrics import roc_auc_score

from tests.anomaly_eval.metrics import wilson_ci
from tests.anomaly_eval.scenarios import (
    LOGIN_GUARD_CASE,
    EGRESS_GUARD_CASE,
    run_egress_scenario,
    run_login_scenario,
)

SEEDS = (0, 1, 2, 3, 4)


def _pool(results, guard_case: str):
    threshold = results[0].shipped_threshold
    normal_scores, loud_scores, subtle_scores = [], [], []
    labels: list[int] = []
    feature_rows: dict[str, list[float]] = {}
    for run in results:
        normal_scores += list(run.normal.values())
        loud_scores += list(run.attacks_where("_loud").values())
        subtle_scores += list(run.attacks_where("_subtle").values())
        attack_ids = {ent for name, ent in run.meta["attack_ids"].items() if name != guard_case}
        for ent, feats in run.meta["features"].items():
            labels.append(1 if ent in attack_ids else 0)
            for name, value in feats.items():
                feature_rows.setdefault(name, []).append(float(value))
    return threshold, normal_scores, loud_scores, subtle_scores, labels, feature_rows


# -------------------------------------------------------------- login

LOGIN_FP_BAND = (0.30, 0.75)
LOGIN_DETECTION_BAND = (0.60, 1.0)
LOGIN_CHANCE_BAND = 0.18  # is_new_geo retains some pooled signal even diluted -- see module docstring
LOGIN_HIDDEN_FEATURES = ("hour", "is_new_geo")

_LOGIN_RESULTS: list | None = None


def _login_results(db_session):
    global _LOGIN_RESULTS
    if _LOGIN_RESULTS is None:
        _LOGIN_RESULTS = [run_login_scenario(db_session, seed=seed) for seed in SEEDS]
    return _LOGIN_RESULTS


@pytest.fixture
def login_pooled(db_session):
    return _pool(_login_results(db_session), LOGIN_GUARD_CASE)


def test_login_false_positive_rate_is_in_a_realistic_band(login_pooled):
    threshold, normal_scores, *_ = login_pooled
    flagged = sum(1 for s in normal_scores if s < threshold)
    rate = flagged / len(normal_scores)
    low, high = wilson_ci(flagged, len(normal_scores))
    band_low, band_high = LOGIN_FP_BAND
    assert band_low <= rate <= band_high, (
        f"FP {rate:.2%} ({flagged}/{len(normal_scores)}), 95% CI [{low:.2%}, {high:.2%}], "
        f"outside the {band_low:.0%}-{band_high:.0%} band"
    )


@pytest.mark.parametrize("feature", LOGIN_HIDDEN_FEATURES)
def test_login_overlap_hides_single_features_near_chance(login_pooled, feature):
    _, _, _, _, labels, feature_rows = login_pooled
    auc = roc_auc_score(labels, feature_rows[feature])
    assert abs(auc - 0.5) <= LOGIN_CHANCE_BAND, (
        f"single-feature AUC for {feature} is {auc:.3f}; overlap should leave it within "
        f"{LOGIN_CHANCE_BAND} of chance (0.5)"
    )


@pytest.mark.parametrize("kind", ["loud", "subtle"])
def test_login_detection_is_in_a_realistic_band(login_pooled, kind):
    threshold, _, loud_scores, subtle_scores, *_ = login_pooled
    scores = loud_scores if kind == "loud" else subtle_scores
    hits = sum(1 for s in scores if s < threshold)
    rate = hits / len(scores)
    low, high = wilson_ci(hits, len(scores))
    band_low, band_high = LOGIN_DETECTION_BAND
    assert band_low <= rate <= band_high, (
        f"{kind} detection {rate:.1%} ({hits}/{len(scores)}), 95% CI [{low:.1%}, {high:.1%}], "
        f"outside the {band_low:.0%}-{band_high:.0%} band"
    )


# -------------------------------------------------------------- egress

EGRESS_FP_BAND = (0.15, 0.45)
EGRESS_DETECTION_BAND = (0.70, 1.0)
EGRESS_CHANCE_BAND = 0.12
EGRESS_HIDDEN_FEATURES = ("bytes_total", "connection_count", "distinct_destinations", "hour")

_EGRESS_RESULTS: list | None = None


def _egress_results(db_session):
    global _EGRESS_RESULTS
    if _EGRESS_RESULTS is None:
        _EGRESS_RESULTS = [run_egress_scenario(db_session, seed=seed) for seed in SEEDS]
    return _EGRESS_RESULTS


@pytest.fixture
def egress_pooled(db_session):
    return _pool(_egress_results(db_session), EGRESS_GUARD_CASE)


def test_egress_false_positive_rate_is_in_a_realistic_band(egress_pooled):
    threshold, normal_scores, *_ = egress_pooled
    flagged = sum(1 for s in normal_scores if s < threshold)
    rate = flagged / len(normal_scores)
    low, high = wilson_ci(flagged, len(normal_scores))
    band_low, band_high = EGRESS_FP_BAND
    assert band_low <= rate <= band_high, (
        f"FP {rate:.2%} ({flagged}/{len(normal_scores)}), 95% CI [{low:.2%}, {high:.2%}], "
        f"outside the {band_low:.0%}-{band_high:.0%} band"
    )


@pytest.mark.parametrize("feature", EGRESS_HIDDEN_FEATURES)
def test_egress_overlap_hides_single_features_near_chance(egress_pooled, feature):
    _, _, _, _, labels, feature_rows = egress_pooled
    auc = roc_auc_score(labels, feature_rows[feature])
    assert abs(auc - 0.5) <= EGRESS_CHANCE_BAND, (
        f"single-feature AUC for {feature} is {auc:.3f}; overlap should leave it within "
        f"{EGRESS_CHANCE_BAND} of chance (0.5)"
    )


@pytest.mark.parametrize("kind", ["loud", "subtle"])
def test_egress_detection_is_in_a_realistic_band(egress_pooled, kind):
    threshold, _, loud_scores, subtle_scores, *_ = egress_pooled
    scores = loud_scores if kind == "loud" else subtle_scores
    hits = sum(1 for s in scores if s < threshold)
    rate = hits / len(scores)
    low, high = wilson_ci(hits, len(scores))
    band_low, band_high = EGRESS_DETECTION_BAND
    assert band_low <= rate <= band_high, (
        f"{kind} detection {rate:.1%} ({hits}/{len(scores)}), 95% CI [{low:.1%}, {high:.1%}], "
        f"outside the {band_low:.0%}-{band_high:.0%} band"
    )
