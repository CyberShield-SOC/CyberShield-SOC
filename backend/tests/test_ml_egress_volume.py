"""IsolationForest pilot #2: egress-volume behavioral anomaly."""

from __future__ import annotations

import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.detection.models import LogRecord
from app.detection.rules.behavioral_anomaly_egress import BehavioralAnomalyEgressRule
from app.ml.features_egress_volume import ENTITY_TYPE, FEATURE_NAMES, egress_volume_features
from app.ml.scoring import load_estimator, score_event
from app.ml.train_egress_volume import train
from app.repositories.ml_repository import count_feature_snapshots, save_feature_snapshot

BASE = datetime(2026, 9, 10, tzinfo=timezone.utc)


def flow(n, host, hour, minute=0, bytes_out=5_000_000, dest="52.95.110.1", src="10.0.4.2"):
    ts = BASE.replace(hour=hour % 24, minute=minute)
    return LogRecord(
        line_number=n, timestamp=ts.strftime("%Y-%m-%dT%H:%M:%SZ"), hostname=host,
        ip_address=src, dest_ip=dest, bytes_out=bytes_out,
    )


@pytest.mark.no_db
def test_features_use_log_scale_and_cyclical_hour():
    quiet = egress_volume_features(BASE.replace(hour=9), bytes_out=1_000_000, connection_count=5, distinct_destinations=1)
    loud = egress_volume_features(BASE.replace(hour=9), bytes_out=1_000_000_000, connection_count=5, distinct_destinations=1)
    assert quiet["log_bytes_out"] < loud["log_bytes_out"]
    assert set(quiet) == set(FEATURE_NAMES)


class TestBehavioralAnomalyEgressRule:
    def test_without_a_db_session_is_a_no_op(self):
        assert BehavioralAnomalyEgressRule().analyze([flow(1, "fs-02", 9)]) == []

    def test_bucketed_bytes_are_captured_as_a_snapshot(self, db_session, monkeypatch):
        feature_set = f"pytest-{uuid4().hex[:8]}"
        monkeypatch.setattr("app.detection.rules.behavioral_anomaly_egress.FEATURE_SET", feature_set)
        host = f"fs-{uuid4().hex[:6]}"

        records = [flow(i, host, 9, minute=i, bytes_out=1_000_000) for i in range(5)]
        alerts = BehavioralAnomalyEgressRule().analyze(records, db_session)

        assert alerts == []  # no model yet
        assert count_feature_snapshots(db_session, feature_set=feature_set, entity_type=ENTITY_TYPE) == 1

    def test_internal_destinations_are_excluded(self, db_session, monkeypatch):
        feature_set = f"pytest-{uuid4().hex[:8]}"
        monkeypatch.setattr("app.detection.rules.behavioral_anomaly_egress.FEATURE_SET", feature_set)
        host = f"fs-{uuid4().hex[:6]}"

        BehavioralAnomalyEgressRule().analyze([flow(1, host, 9, dest="10.0.9.9")], db_session)
        assert count_feature_snapshots(db_session, feature_set=feature_set, entity_type=ENTITY_TYPE) == 0


def _train_quiet_host_model(db_session, feature_set: str, random_state: int = 42):
    """150 hourly buckets, ~5MB +/- jitter, 1-3 destinations, business hours
    — a real (if narrow) distribution, per the same lesson learned on the
    login-behavior pilot: rigid duplicate points collapse IsolationForest's
    splits into meaningless identical scores."""

    rng = random.Random(99)
    for i in range(150):
        hour = 9 + rng.uniform(-1.0, 1.0)
        bytes_out = int(5_000_000 * rng.uniform(0.8, 1.2))
        ts = BASE.replace(hour=int(hour) % 24, minute=int((hour % 1) * 60))
        save_feature_snapshot(
            db_session, feature_set=feature_set, entity_type=ENTITY_TYPE,
            entity_id=f"host-{i % 6}", captured_at=ts,
            features=egress_volume_features(ts, bytes_out=bytes_out, connection_count=rng.randint(3, 8), distinct_destinations=rng.randint(1, 3)),
        )
    return train(db_session, min_samples=50, random_state=random_state)


def _midpoint_threshold(model_row, normal: dict, outlier: dict) -> float:
    estimator = load_estimator(model_row)
    normal_score = score_event(model_row, estimator, normal).score
    outlier_score = score_event(model_row, estimator, outlier).score
    assert outlier_score < normal_score
    return (normal_score + outlier_score) / 2


class TestBehavioralAnomalyEgressScoring:
    def test_volume_spike_at_odd_hour_fires_once_shadow_mode_is_off(self, db_session, monkeypatch):
        feature_set = f"pytest-{uuid4().hex[:8]}"
        monkeypatch.setattr("app.detection.rules.behavioral_anomaly_egress.FEATURE_SET", feature_set)
        monkeypatch.setattr("app.ml.train_egress_volume.FEATURE_SET", feature_set)
        model_row = _train_quiet_host_model(db_session, feature_set)

        host = f"host-{uuid4().hex[:6]}"
        normal = egress_volume_features(BASE.replace(hour=9, minute=15), bytes_out=5_000_000, connection_count=5, distinct_destinations=2)
        outlier_features = egress_volume_features(BASE.replace(hour=3), bytes_out=900_000_000, connection_count=40, distinct_destinations=9)
        threshold = _midpoint_threshold(model_row, normal, outlier_features)

        record = flow(1, host, 3, bytes_out=900_000_000, dest="91.198.174.192")
        # A 40-connection, 9-destination spike needs more than one record.
        records = [record] + [flow(i + 2, host, 3, bytes_out=1, dest=f"91.198.174.{i}") for i in range(39)]

        alerts = BehavioralAnomalyEgressRule(
            params={"score_threshold": threshold, "shadow_mode": False}
        ).analyze(records, db_session)

        assert len(alerts) == 1
        alert = alerts[0]
        assert alert.rule == "behavioral_anomaly_egress"
        assert alert.entity_type == "host"
        assert alert.entity_id == host
        assert alert.evidence["score"] < alert.evidence["threshold"]
        assert "bytes_out" in alert.evidence

    def test_shadow_mode_default_suppresses_the_same_alert(self, db_session, monkeypatch):
        feature_set = f"pytest-{uuid4().hex[:8]}"
        monkeypatch.setattr("app.detection.rules.behavioral_anomaly_egress.FEATURE_SET", feature_set)
        monkeypatch.setattr("app.ml.train_egress_volume.FEATURE_SET", feature_set)
        _train_quiet_host_model(db_session, feature_set)

        host = f"host-{uuid4().hex[:6]}"
        records = [flow(i + 1, host, 3, bytes_out=900_000_000, dest=f"91.198.174.{i}") for i in range(40)]

        assert BehavioralAnomalyEgressRule().analyze(records, db_session) == []
