"""
Which `train_*.py` module owns which feature_set — the one place
POST /ml/models/{feature_set}/train needs to know about, so adding a third
pilot means adding one line here, not touching the router.
"""

from __future__ import annotations

from app.ml import train_egress_volume, train_login_behavior, train_threat_detection

TRAINERS = {
    train_login_behavior.FEATURE_SET: train_login_behavior.train,
    train_egress_volume.FEATURE_SET: train_egress_volume.train,
    train_threat_detection.FEATURE_SET: train_threat_detection.train,
}

# One record per pilot: entity_type + min_samples read off each train_*.py
# module (so they can't drift), plus the detection rule that consumes the
# feature_set (app/detection/rules/behavioral_anomaly_*.py). rule_name is a
# plain string rather than an imported class: the rules import
# app.ml.pipeline, and app.detection's package __init__ explains why this
# package must not import them back. tests/test_ml_models_api.py asserts
# every rule_name here is a registered rule. Backs GET /ml/anomalies.
TRAINER_META = {
    train_login_behavior.FEATURE_SET: {
        "entity_type": train_login_behavior.ENTITY_TYPE,
        "min_samples": train_login_behavior.MIN_SAMPLES,
        "rule_name": "behavioral_anomaly_login",
    },
    train_egress_volume.FEATURE_SET: {
        "entity_type": train_egress_volume.ENTITY_TYPE,
        "min_samples": train_egress_volume.MIN_SAMPLES,
        "rule_name": "behavioral_anomaly_egress",
    },
    train_threat_detection.FEATURE_SET: {
        "entity_type": train_threat_detection.ENTITY_TYPE,
        "min_samples": train_threat_detection.MIN_SAMPLES,
        "rule_name": "behavioral_anomaly_threat_log",
    },
}


def get_trainer(feature_set: str):
    return TRAINERS.get(feature_set)


def list_feature_sets() -> list[str]:
    """Pilots the read-only endpoints report on: every TRAINER_META entry.
    (TRAINERS alone can be patched in tests without metadata; iterating it
    here would turn those read-only routes into a KeyError.)"""

    return list(TRAINER_META.keys())
