"""
IsolationForest login-behavior pilot: feature extraction, the repository,
offline training (app/ml/train_login_behavior.py), and the scoring rule
(BehavioralAnomalyLoginRule). All model-fitting tests use a fixed
random_state, per the feasibility doc's non-flaky-testing requirement.
"""

from __future__ import annotations

import math
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.detection.models import LogRecord
from app.detection.rules.behavioral_anomaly_login import BehavioralAnomalyLoginRule
from app.ml.features import ENTITY_TYPE, FEATURE_NAMES, FEATURE_SET, login_behavior_features, vector
from app.ml.train_login_behavior import InsufficientTrainingDataError, train
from app.repositories.baseline_repository import get_baseline
from app.ml.scoring import load_estimator, score_event
from app.repositories.ml_repository import (
    count_feature_snapshots,
    get_active_model,
    list_feature_snapshots,
    list_scored_snapshots,
    save_feature_snapshot,
    save_model,
)

BASE = datetime(2026, 9, 10, tzinfo=timezone.utc)


def login(n, user, hour, minute=0, day_offset=0, country=None, ip="10.0.0.9"):
    ts = (BASE + timedelta(days=day_offset)).replace(hour=hour, minute=minute)
    return LogRecord(
        line_number=n, timestamp=ts.strftime("%Y-%m-%dT%H:%M:%SZ"), username=user, ip_address=ip,
        event_type="login_attempt", status="SUCCESS", country=country,
    )


# ── feature extraction (pure, no_db) ────────────────────────────────────────

@pytest.mark.no_db
class TestLoginBehaviorFeatures:
    def test_midnight_wraps_continuously(self):
        just_before = login_behavior_features(BASE.replace(hour=23, minute=59), is_new_geo=False)
        just_after = login_behavior_features(BASE.replace(hour=0, minute=1), is_new_geo=False)
        # 2 minutes apart on the clock -> close on the unit circle, not at
        # opposite ends of a raw 0-23 scale.
        distance = math.hypot(just_before["hour_sin"] - just_after["hour_sin"], just_before["hour_cos"] - just_after["hour_cos"])
        assert distance < 0.1

    def test_is_new_geo_flag_passes_through(self):
        assert login_behavior_features(BASE, is_new_geo=True)["is_new_geo"] == 1.0
        assert login_behavior_features(BASE, is_new_geo=False)["is_new_geo"] == 0.0

    def test_vector_preserves_feature_order(self):
        features = login_behavior_features(BASE.replace(hour=14), is_new_geo=True)
        assert vector(features, FEATURE_NAMES) == [features[name] for name in FEATURE_NAMES]

    def test_vector_raises_on_missing_feature(self):
        with pytest.raises(KeyError):
            vector({"hour_sin": 0.0}, FEATURE_NAMES)


# ── repository ───────────────────────────────────────────────────────────────

def test_snapshot_round_trip_and_count(db_session):
    entity = f"acct-{uuid4().hex[:8]}"
    assert count_feature_snapshots(db_session, feature_set=FEATURE_SET, entity_type=ENTITY_TYPE) >= 0

    before = count_feature_snapshots(db_session, feature_set=FEATURE_SET, entity_type=ENTITY_TYPE)
    save_feature_snapshot(
        db_session, feature_set=FEATURE_SET, entity_type=ENTITY_TYPE,
        entity_id=entity, captured_at=BASE, features={"hour_sin": 0.5},
    )
    after = count_feature_snapshots(db_session, feature_set=FEATURE_SET, entity_type=ENTITY_TYPE)
    assert after == before + 1

    rows = list_feature_snapshots(db_session, feature_set=FEATURE_SET, entity_type=ENTITY_TYPE)
    assert any(row.entity_id == entity for row in rows)


def test_save_model_versions_and_deactivates_previous(db_session):
    feature_set = f"pytest-{uuid4().hex[:8]}"
    first = save_model(
        db_session, feature_set=feature_set, entity_type=ENTITY_TYPE, feature_names=list(FEATURE_NAMES),
        feature_means={}, feature_stds={}, model_bytes=b"v1", sample_count=10, contamination=None,
        params={}, created_by=None,
    )
    second = save_model(
        db_session, feature_set=feature_set, entity_type=ENTITY_TYPE, feature_names=list(FEATURE_NAMES),
        feature_means={}, feature_stds={}, model_bytes=b"v2", sample_count=20, contamination=None,
        params={}, created_by=None,
    )
    assert (first.version, second.version) == (1, 2)

    db_session.refresh(first)
    assert first.is_active is False
    assert second.is_active is True

    active = get_active_model(db_session, feature_set=feature_set, entity_type=ENTITY_TYPE)
    assert active.id == second.id


def test_save_model_can_skip_activation(db_session):
    feature_set = f"pytest-{uuid4().hex[:8]}"
    row = save_model(
        db_session, feature_set=feature_set, entity_type=ENTITY_TYPE, feature_names=list(FEATURE_NAMES),
        feature_means={}, feature_stds={}, model_bytes=b"v1", sample_count=10, contamination=None,
        params={}, created_by=None, activate=False,
    )
    assert row.is_active is False
    assert get_active_model(db_session, feature_set=feature_set, entity_type=ENTITY_TYPE) is None


# ── training ─────────────────────────────────────────────────────────────────

def _seed_snapshots(db_session, feature_set: str, count: int) -> None:
    for i in range(count):
        hour = 9 if i % 2 == 0 else 10  # tight, boring, "normal" cluster
        save_feature_snapshot(
            db_session, feature_set=feature_set, entity_type=ENTITY_TYPE,
            entity_id=f"acct-{i % 5}", captured_at=BASE + timedelta(minutes=i),
            features=login_behavior_features(BASE.replace(hour=hour), is_new_geo=False),
        )


def test_train_raises_below_minimum_samples(db_session, monkeypatch):
    feature_set = f"pytest-{uuid4().hex[:8]}"
    monkeypatch.setattr("app.ml.train_login_behavior.FEATURE_SET", feature_set)
    _seed_snapshots(db_session, feature_set, 10)

    with pytest.raises(InsufficientTrainingDataError) as exc_info:
        train(db_session, min_samples=50)
    assert exc_info.value.sample_count == 10


def test_train_fits_and_saves_an_active_model(db_session, monkeypatch):
    feature_set = f"pytest-{uuid4().hex[:8]}"
    monkeypatch.setattr("app.ml.train_login_behavior.FEATURE_SET", feature_set)
    _seed_snapshots(db_session, feature_set, 60)

    saved = train(db_session, min_samples=50, random_state=7)

    assert saved.feature_set == feature_set
    assert saved.entity_type == ENTITY_TYPE
    assert saved.sample_count == 60
    assert saved.feature_names == list(FEATURE_NAMES)
    assert saved.is_active is True
    assert saved.params == {"n_estimators": 100, "max_samples": 60, "random_state": 7}
    assert set(saved.feature_means) == set(FEATURE_NAMES)

    active = get_active_model(db_session, feature_set=feature_set, entity_type=ENTITY_TYPE)
    assert active.id == saved.id


def test_near_constant_feature_does_not_blow_up_z_scores(db_session, monkeypatch):
    """Regression: training data drawn from a single calendar day gives
    dow_sin/dow_cos ~zero variance (floating-point std ~1e-16, not a clean
    0.0) — caught live when a real upload produced a z-score in the
    hundreds of trillions instead of being floored. See train_login_behavior.py."""

    feature_set = f"pytest-{uuid4().hex[:8]}"
    monkeypatch.setattr("app.ml.train_login_behavior.FEATURE_SET", feature_set)
    _seed_snapshots(db_session, feature_set, 60)  # all on the same calendar day

    saved = train(db_session, min_samples=50, random_state=7)

    assert saved.feature_stds["dow_sin"] == 1.0
    assert saved.feature_stds["dow_cos"] == 1.0

    estimator = load_estimator(saved)
    different_weekday = login_behavior_features(BASE + timedelta(days=3, hours=9), is_new_geo=False)
    scored = score_event(saved, estimator, different_weekday)
    dow_deviations = [d for d in scored.deviations if d.feature.startswith("dow_")]
    assert all(abs(d.z_score) <= 3 for d in dow_deviations)


def test_retraining_produces_a_new_version(db_session, monkeypatch):
    feature_set = f"pytest-{uuid4().hex[:8]}"
    monkeypatch.setattr("app.ml.train_login_behavior.FEATURE_SET", feature_set)
    _seed_snapshots(db_session, feature_set, 50)
    first = train(db_session, min_samples=50, random_state=1)
    _seed_snapshots(db_session, feature_set, 10)
    second = train(db_session, min_samples=50, random_state=1)

    assert second.version == first.version + 1
    assert second.sample_count == 60
    db_session.refresh(first)
    assert first.is_active is False


# ── scoring rule ─────────────────────────────────────────────────────────────

def _train_normal_business_hours_model(db_session, feature_set: str, random_state: int = 42):
    """150 logins jittered ±1h around 9am — a real, if narrow, distribution,
    not a two-point degenerate one. IsolationForest needs actual variance to
    split on; a rigid alternating pattern collapses to duplicate points and
    produces meaningless (identical) scores for everything, outlier included."""

    rng = random.Random(123)
    for i in range(150):
        hour = 9 + rng.uniform(-1.0, 1.0)
        ts = BASE.replace(hour=int(hour) % 24, minute=int((hour % 1) * 60))
        save_feature_snapshot(
            db_session, feature_set=feature_set, entity_type=ENTITY_TYPE,
            entity_id=f"acct-{i % 8}", captured_at=ts,
            features=login_behavior_features(ts, is_new_geo=False),
        )
    from app.ml.train_login_behavior import train as _train
    return _train(db_session, min_samples=50, random_state=random_state)


def _midpoint_threshold(model_row, normal_features: dict, outlier_features: dict) -> float:
    """Derive a score cutoff from the model's own output on a known-normal
    and a known-outlier point, rather than hardcoding a score value that
    depends on scikit-learn's internal calibration — robust to library
    version drift, not just to the random seed."""

    estimator = load_estimator(model_row)
    normal_score = score_event(model_row, estimator, normal_features).score
    outlier_score = score_event(model_row, estimator, outlier_features).score
    assert outlier_score < normal_score, "fixture regression: outlier scored as more normal than normal"
    return (normal_score + outlier_score) / 2


class TestBehavioralAnomalyLoginRule:
    def test_without_a_trained_model_only_collects_snapshots(self, db_session, monkeypatch):
        feature_set = f"pytest-{uuid4().hex[:8]}"
        monkeypatch.setattr("app.detection.rules.behavioral_anomaly_login.FEATURE_SET", feature_set)
        user = f"acct-{uuid4().hex[:8]}"

        alerts = BehavioralAnomalyLoginRule().analyze([login(1, user, hour=9)], db_session)

        assert alerts == []
        assert count_feature_snapshots(db_session, feature_set=feature_set, entity_type=ENTITY_TYPE) == 1

    def test_without_a_db_session_is_a_no_op(self):
        assert BehavioralAnomalyLoginRule().analyze([login(1, "anyone", hour=9)]) == []

    def test_planted_outlier_fires_once_a_model_exists(self, db_session, monkeypatch):
        feature_set = f"pytest-{uuid4().hex[:8]}"
        monkeypatch.setattr("app.detection.rules.behavioral_anomaly_login.FEATURE_SET", feature_set)
        monkeypatch.setattr("app.ml.train_login_behavior.FEATURE_SET", feature_set)
        model_row = _train_normal_business_hours_model(db_session, feature_set)

        user = f"acct-{uuid4().hex[:8]}"
        # 3am login from a never-seen country, for a population trained
        # exclusively on ~9am (+/-1h) logins from known countries.
        outlier = login(1, user, hour=3, country="KP")
        threshold = _midpoint_threshold(
            model_row,
            login_behavior_features(BASE.replace(hour=9, minute=15), is_new_geo=False),
            login_behavior_features(BASE.replace(hour=3), is_new_geo=True),
        )

        alerts = BehavioralAnomalyLoginRule(
            params={"score_threshold": threshold, "shadow_mode": False}
        ).analyze([outlier], db_session)

        assert len(alerts) == 1
        alert = alerts[0]
        assert alert.rule == "behavioral_anomaly_login"
        assert alert.entity_type == "account"
        assert alert.entity_id == user
        assert alert.severity == "LOW"
        assert alert.evidence["score"] < alert.evidence["threshold"]
        deviated_features = {d["feature"] for d in alert.evidence["feature_deviations"]}
        assert deviated_features & {"hour_sin", "hour_cos", "is_new_geo"}
        assert alert.evidence["model_sample_count"] == 150

    def test_normal_hour_login_does_not_fire(self, db_session, monkeypatch):
        feature_set = f"pytest-{uuid4().hex[:8]}"
        monkeypatch.setattr("app.detection.rules.behavioral_anomaly_login.FEATURE_SET", feature_set)
        monkeypatch.setattr("app.ml.train_login_behavior.FEATURE_SET", feature_set)
        model_row = _train_normal_business_hours_model(db_session, feature_set)

        user = f"acct-{uuid4().hex[:8]}"
        normal = login(1, user, hour=9, minute=15, country="US")
        threshold = _midpoint_threshold(
            model_row,
            login_behavior_features(BASE.replace(hour=9, minute=15), is_new_geo=False),
            login_behavior_features(BASE.replace(hour=3), is_new_geo=True),
        )

        alerts = BehavioralAnomalyLoginRule(
            params={"score_threshold": threshold, "shadow_mode": False}
        ).analyze([normal], db_session)
        assert alerts == []

    def test_shadow_mode_scores_and_stores_but_never_alerts(self, db_session, monkeypatch):
        """The feasibility doc's §5.5 rollout requirement: an admin must be
        able to see what a rule *would* flag before it can alert for real."""

        feature_set = f"pytest-{uuid4().hex[:8]}"
        monkeypatch.setattr("app.detection.rules.behavioral_anomaly_login.FEATURE_SET", feature_set)
        monkeypatch.setattr("app.ml.train_login_behavior.FEATURE_SET", feature_set)
        model_row = _train_normal_business_hours_model(db_session, feature_set)

        user = f"acct-{uuid4().hex[:8]}"
        outlier = login(1, user, hour=3, country="KP")
        threshold = _midpoint_threshold(
            model_row,
            login_behavior_features(BASE.replace(hour=9, minute=15), is_new_geo=False),
            login_behavior_features(BASE.replace(hour=3), is_new_geo=True),
        )

        # shadow_mode defaults to True — the rule must not need it spelled out.
        rule = BehavioralAnomalyLoginRule(params={"score_threshold": threshold})
        assert rule.params["shadow_mode"] is True

        alerts = rule.analyze([outlier], db_session)
        assert alerts == []

        reviewed = list_scored_snapshots(db_session, feature_set=feature_set, entity_type=ENTITY_TYPE, below=threshold)
        assert len(reviewed) == 1
        assert reviewed[0].entity_id == user
        assert reviewed[0].score < threshold

    def test_shadow_mode_can_be_turned_off_via_the_standard_params_mechanism(self, db_session, monkeypatch):
        feature_set = f"pytest-{uuid4().hex[:8]}"
        monkeypatch.setattr("app.detection.rules.behavioral_anomaly_login.FEATURE_SET", feature_set)
        monkeypatch.setattr("app.ml.train_login_behavior.FEATURE_SET", feature_set)
        model_row = _train_normal_business_hours_model(db_session, feature_set)

        user = f"acct-{uuid4().hex[:8]}"
        outlier = login(1, user, hour=3, country="KP")
        threshold = _midpoint_threshold(
            model_row,
            login_behavior_features(BASE.replace(hour=9, minute=15), is_new_geo=False),
            login_behavior_features(BASE.replace(hour=3), is_new_geo=True),
        )

        from app.detection.engine import DetectionEngine
        from app.detection.models import RuleConfig

        rule = DetectionEngine.rule_from_config(
            BehavioralAnomalyLoginRule,
            RuleConfig(params={"score_threshold": threshold, "shadow_mode": False}),
        )
        assert rule.params["shadow_mode"] is False
        assert len(rule.analyze([outlier], db_session)) == 1

    def test_model_with_mismatched_feature_schema_is_treated_as_absent(self, db_session, monkeypatch):
        feature_set = f"pytest-{uuid4().hex[:8]}"
        monkeypatch.setattr("app.detection.rules.behavioral_anomaly_login.FEATURE_SET", feature_set)
        save_model(
            db_session, feature_set=feature_set, entity_type=ENTITY_TYPE,
            feature_names=["some_other_feature"], feature_means={}, feature_stds={},
            model_bytes=b"not-actually-a-model", sample_count=999, contamination=None,
            params={}, created_by=None,
        )
        user = f"acct-{uuid4().hex[:8]}"

        alerts = BehavioralAnomalyLoginRule().analyze([login(1, user, hour=3, country="KP")], db_session)

        assert alerts == []  # never attempts to unpickle the bogus bytes

    def test_uses_its_own_baseline_key_independent_of_first_seen_geo_asn(self, db_session, monkeypatch):
        """Regression guard: this rule must not read a country as 'known'
        just because first_seen_geo_asn already flushed it for the same
        batch earlier in engine.run()'s rule order."""
        feature_set = f"pytest-{uuid4().hex[:8]}"
        monkeypatch.setattr("app.detection.rules.behavioral_anomaly_login.FEATURE_SET", feature_set)
        user = f"acct-{uuid4().hex[:8]}"

        from app.detection.rules.first_seen_geo_asn import FirstSeenGeoAsnRule
        event = login(1, user, hour=9, country="NL")

        # Simulate first_seen_geo_asn having already run first in the same
        # engine.run() pass, per _RULE_CLASSES order.
        FirstSeenGeoAsnRule().analyze([event], db_session)

        rows = list_feature_snapshots(db_session, feature_set=feature_set, entity_type=ENTITY_TYPE)
        before = len(rows)
        BehavioralAnomalyLoginRule().analyze([event], db_session)
        after = list_feature_snapshots(db_session, feature_set=feature_set, entity_type=ENTITY_TYPE)
        assert len(after) == before + 1
        assert after[-1].features["is_new_geo"] == 1.0
