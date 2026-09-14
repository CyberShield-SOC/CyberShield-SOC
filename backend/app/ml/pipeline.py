"""
Shared plumbing between every anomaly rule and every training script:
loading whichever model is currently active, scoring one event against it,
and persisting the result as training history (with its score attached, so
shadow-mode runs stay reviewable instead of silent — see MLFeatureSnapshot's
docstring). Both behavioral_anomaly_login.py and behavioral_anomaly_egress.py
call this; it holds no feature-set-specific knowledge of its own.
"""

from __future__ import annotations

import io
from datetime import datetime

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sqlalchemy.orm import Session

from app.ml.scoring import ScoredEvent, load_estimator, score_event
from app.models.ml_feature_snapshot import MLFeatureSnapshot
from app.models.ml_model import MLModel
from app.repositories.ml_repository import get_active_model, list_feature_snapshots, save_feature_snapshot, save_model


class InsufficientTrainingDataError(RuntimeError):
    """Raised by a training script when there aren't enough stored snapshots
    to fit a model yet. Shared across training scripts so the API layer
    (POST /ml/models/{feature_set}/train) only needs to catch one type."""

    def __init__(self, feature_set: str, sample_count: int, minimum: int):
        self.feature_set = feature_set
        self.sample_count = sample_count
        self.minimum = minimum
        super().__init__(
            f"Only {sample_count} {feature_set} snapshot(s) stored; need at least {minimum}. "
            "Upload more data first."
        )


def load_active(
    db: Session, *, feature_set: str, entity_type: str, feature_names: tuple[str, ...]
) -> tuple[MLModel | None, object | None]:
    """
    The active model + its deserialized estimator, or (None, None).

    Call this once per analyze() batch, not once per event — deserializing a
    joblib model isn't free, and it doesn't change mid-batch. A model whose
    feature schema doesn't match `feature_names` (a stale pilot version, an
    unrelated feature_set collision) is treated identically to no model at
    all — never scored against, never misread.
    """

    model_row = get_active_model(db, feature_set=feature_set, entity_type=entity_type)
    if model_row is None or model_row.feature_names != list(feature_names):
        return None, None
    return model_row, load_estimator(model_row)


def record_and_score(
    db: Session,
    *,
    feature_set: str,
    entity_type: str,
    entity_id: str,
    captured_at: datetime,
    features: dict[str, float],
    model_row: MLModel | None,
    estimator,
) -> tuple[MLFeatureSnapshot, ScoredEvent | None]:
    """
    Persist one training sample and, if a model is loaded, score it too.

    Every event gets a snapshot regardless of whether a model exists — that
    snapshot *is* the training data a future `train_*` run will use. The
    score (when available) rides along on the same row rather than a
    separate table, so "what would this have flagged" is always answerable
    from one place.
    """

    scored = score_event(model_row, estimator, features) if estimator is not None else None
    snapshot = save_feature_snapshot(
        db,
        feature_set=feature_set,
        entity_type=entity_type,
        entity_id=entity_id,
        captured_at=captured_at,
        features=features,
        score=scored.score if scored is not None else None,
    )
    return snapshot, scored


def fit_and_save_model(
    db: Session,
    *,
    feature_set: str,
    entity_type: str,
    feature_names: tuple[str, ...],
    min_samples: int,
    random_state: int,
    created_by: int | None = None,
    activate: bool = True,
) -> MLModel:
    """
    Shared IsolationForest fit-and-persist step, used by every `train_*.py`
    script. Pulls the whole pooled population for (feature_set, entity_type)
    (see list_feature_snapshots — pooled, not per-entity, per the
    feasibility doc's §3.3 tradeoff), fits one forest, and saves it as a new
    version. Caller commits.

    Raises InsufficientTrainingDataError below `min_samples`. Each
    `train_*.py` module owns its own MIN_SAMPLES/RANDOM_STATE constants and
    docstring context (why this feature_set, what "enough data" means for
    it) — this function only knows the mechanical fit-and-save step, not
    which feature_set is being trained.
    """

    snapshots = list_feature_snapshots(db, feature_set=feature_set, entity_type=entity_type)
    if len(snapshots) < min_samples:
        raise InsufficientTrainingDataError(feature_set, len(snapshots), min_samples)

    matrix = np.array(
        [[float(row.features[name]) for name in feature_names] for row in snapshots],
        dtype=float,
    )
    max_samples = min(256, matrix.shape[0])

    model = IsolationForest(
        n_estimators=100, max_samples=max_samples, contamination="auto", random_state=random_state,
    )
    model.fit(matrix)

    buffer = io.BytesIO()
    joblib.dump(model, buffer)

    means = matrix.mean(axis=0)
    stds = matrix.std(axis=0)
    # A near-constant feature (e.g. training data drawn from a single
    # calendar day gives dow_sin ~zero variance, or a quiet host has
    # log_bytes_out barely moving) produces a std of order 1e-16 from
    # floating-point summation, not a clean 0.0 — an exact-zero guard alone
    # misses that and z-scores explode. This is a real bug this project hit
    # via live testing, not a hypothetical — see the feasibility doc's
    # "Implementation status" section.
    stds[stds < 1e-6] = 1.0

    return save_model(
        db,
        feature_set=feature_set,
        entity_type=entity_type,
        feature_names=list(feature_names),
        feature_means=dict(zip(feature_names, means.tolist())),
        feature_stds=dict(zip(feature_names, stds.tolist())),
        model_bytes=buffer.getvalue(),
        sample_count=matrix.shape[0],
        contamination=None,  # "auto" — scikit-learn doesn't expose the resolved value pre-fit
        params={"n_estimators": 100, "max_samples": max_samples, "random_state": random_state},
        created_by=created_by,
        activate=activate,
    )
