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


def get_trainer(feature_set: str):
    return TRAINERS.get(feature_set)
