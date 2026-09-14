"""
Offline training for the login-behavior IsolationForest pilot.

Deliberately NOT part of the FastAPI request path (see the feasibility
doc's §5.3) — run this by hand:

    cd backend && .venv/Scripts/python.exe -m app.ml.train_login_behavior

or trigger it through POST /ml/models/login_behavior/train (Admin only —
see app/routers/ml_models.py).

It pulls every stored `login_behavior` feature snapshot (populated by
BehavioralAnomalyLoginRule on every upload — see
app/detection/rules/behavioral_anomaly_login.py), fits one pooled
IsolationForest across all accounts, and saves it as the new active model.
Until this has been run at least once, that rule only collects snapshots
and never scores anything — the first of two shadow-mode gates (see
MLModel's docstring and BehavioralAnomalyLoginRule's).
"""

from __future__ import annotations

import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app.ml.features import ENTITY_TYPE, FEATURE_NAMES, FEATURE_SET
from app.ml.pipeline import InsufficientTrainingDataError, fit_and_save_model

__all__ = ["train", "main", "InsufficientTrainingDataError", "MIN_SAMPLES", "RANDOM_STATE"]

# Below this, any fitted model would mostly be noise — scikit-learn's own
# max_samples default is 256; this project's docs explicitly warn that a
# demo/lab deployment's own sample-logs never approach real training volume
# (see the feasibility doc's §3.3). 50 is a floor for *this pilot to run at
# all*, not a claim that 50 samples produce a trustworthy model.
MIN_SAMPLES = 50
RANDOM_STATE = 42  # fixed for reproducible tests (feasibility doc §5.4) and stable scoring


def train(
    db,
    *,
    min_samples: int = MIN_SAMPLES,
    random_state: int = RANDOM_STATE,
    created_by: int | None = None,
    activate: bool = True,
):
    """Fit and persist one new model version. Raises InsufficientTrainingDataError
    if there isn't enough stored history yet. Caller commits."""

    return fit_and_save_model(
        db,
        feature_set=FEATURE_SET,
        entity_type=ENTITY_TYPE,
        feature_names=FEATURE_NAMES,
        min_samples=min_samples,
        random_state=random_state,
        created_by=created_by,
        activate=activate,
    )


def main() -> int:
    from app.db.session import SessionLocal

    with SessionLocal() as db:
        try:
            saved = train(db)
        except InsufficientTrainingDataError as exc:
            print(f"Not trained: {exc}")
            return 1
        db.commit()
        print(
            f"Trained {saved.feature_set}/{saved.entity_type} v{saved.version} "
            f"on {saved.sample_count} samples, now active."
        )
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
