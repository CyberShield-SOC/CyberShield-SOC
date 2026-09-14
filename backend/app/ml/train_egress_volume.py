"""
Offline training for the egress-volume IsolationForest pilot.

    cd backend && .venv/Scripts/python.exe -m app.ml.train_egress_volume

or POST /ml/models/egress_volume/train (Admin only). See
train_login_behavior.py's docstring for the shared shape; this differs only
in feature_set/entity_type/minimum-volume reasoning.
"""

from __future__ import annotations

import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app.ml.features_egress_volume import ENTITY_TYPE, FEATURE_NAMES, FEATURE_SET
from app.ml.pipeline import InsufficientTrainingDataError, fit_and_save_model

__all__ = ["train", "main", "InsufficientTrainingDataError", "MIN_SAMPLES", "RANDOM_STATE"]

# Hourly buckets, pooled across hosts — 50 hourly buckets is roughly two
# days of continuous multi-host traffic, still thin (see the feasibility
# doc's §3.3) but enough for this pilot to produce a non-degenerate fit.
MIN_SAMPLES = 50
RANDOM_STATE = 42


def train(
    db,
    *,
    min_samples: int = MIN_SAMPLES,
    random_state: int = RANDOM_STATE,
    created_by: int | None = None,
    activate: bool = True,
):
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
