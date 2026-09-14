"""
Scoring + explainability for a saved IsolationForest model.

Loading and unpickling happen once per upload batch (see
app/detection/rules/behavioral_anomaly_login.py), not once per event —
IsolationForest itself is fast to score with, but there's no reason to
repeat the deserialization.
"""

from __future__ import annotations

import io
from dataclasses import dataclass

import joblib

from app.models.ml_model import MLModel


class ModelSchemaMismatchError(RuntimeError):
    """The caller's feature order doesn't match what this model was trained on."""


@dataclass
class FeatureDeviation:
    feature: str
    value: float
    mean: float
    z_score: float


@dataclass
class ScoredEvent:
    # scikit-learn's decision_function: > 0 normal, < 0 anomalous, roughly
    # centered on 0 — unlike score_samples, a fixed "< 0" is already a
    # meaningful default cutoff before any deployment-specific tuning.
    score: float
    deviations: list[FeatureDeviation]

    def top_deviations(self, count: int = 3) -> list[FeatureDeviation]:
        return sorted(self.deviations, key=lambda d: abs(d.z_score), reverse=True)[:count]


def load_estimator(model_row: MLModel):
    return joblib.load(io.BytesIO(model_row.model_bytes))


def score_event(model_row: MLModel, estimator, features: dict[str, float]) -> ScoredEvent:
    """Score one feature dict against a loaded model. `features` must contain
    every name in `model_row.feature_names` — anything else is a caller bug,
    not a data problem, so this raises rather than silently defaulting."""

    missing = [name for name in model_row.feature_names if name not in features]
    if missing:
        raise ModelSchemaMismatchError(f"Missing feature(s) for scoring: {', '.join(missing)}")

    ordered = [float(features[name]) for name in model_row.feature_names]
    score = float(estimator.decision_function([ordered])[0])

    deviations = [
        FeatureDeviation(
            feature=name,
            value=value,
            mean=model_row.feature_means.get(name, 0.0),
            z_score=(value - model_row.feature_means.get(name, 0.0)) / (model_row.feature_stds.get(name, 1.0) or 1.0),
        )
        for name, value in zip(model_row.feature_names, ordered)
    ]
    return ScoredEvent(score=score, deviations=deviations)
