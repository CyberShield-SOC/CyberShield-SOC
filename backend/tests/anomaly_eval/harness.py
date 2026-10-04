"""Isolated, seeded scenarios for the learned-anomaly (IsolationForest) rules.

Every scenario is fully synthetic and self-contained: no dataset files, no
network, no shared state. The shape is always the same:

    1. ingest a seeded "normal" history (rule.analyze stores feature snapshots),
    2. train a real model on those snapshots,
    3. ingest one more period containing normal behaviour plus injected anomalies,
    4. read back the IsolationForest scores the rule persisted.

Isolation. The rules and the training modules read a module-level FEATURE_SET
name, and the training pool is "every snapshot stored under that name". A
scenario therefore (a) swaps in a name that is unique to it, in both modules,
(b) restores the originals when it ends, even on error, and (c) rolls back every
database change in a savepoint. Two scenarios run in one process (or one DB
transaction) cannot see each other's snapshots, models or baselines.

NOT thread-safe: the swap is process-global. pytest-xdist uses separate
processes, so that is fine; do not run scenarios from threads.
"""

from __future__ import annotations

import importlib
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from uuid import uuid4

from sqlalchemy.orm import Session

from app.repositories.ml_repository import count_feature_snapshots, list_feature_snapshots


@dataclass(frozen=True)
class FeatureSetSpec:
    key: str
    entity_type: str
    rule_module: str
    rule_class: str
    train_module: str
    min_samples: int = 50

    def rule_cls(self):
        return getattr(importlib.import_module(self.rule_module), self.rule_class)

    def shipped_threshold(self) -> float:
        """The score_threshold the product ships with: what a real deployment uses."""

        return float(self.rule_cls().DEFAULT_PARAMS["score_threshold"])


SPECS: dict[str, FeatureSetSpec] = {
    "login": FeatureSetSpec(
        "login", "account",
        "app.detection.rules.behavioral_anomaly_login", "BehavioralAnomalyLoginRule",
        "app.ml.train_login_behavior",
    ),
    "egress": FeatureSetSpec(
        "egress", "host",
        "app.detection.rules.behavioral_anomaly_egress", "BehavioralAnomalyEgressRule",
        "app.ml.train_egress_volume",
    ),
    "threat_log": FeatureSetSpec(
        "threat_log", "source_ip",
        "app.detection.rules.behavioral_anomaly_threat_log", "BehavioralAnomalyThreatLogRule",
        "app.ml.train_threat_detection",
    ),
}


@dataclass
class Scenario:
    """One isolated scenario: a unique feature-set name bound to a DB session."""

    spec: FeatureSetSpec
    feature_set: str
    db: Session
    trained: bool = field(default=False, init=False)

    def rule(self, **params):
        # shadow_mode stays at its shipped default (True): scores are persisted
        # either way, and these evals read scores, not alerts.
        return self.spec.rule_cls()(params=params or None)

    def ingest(self, records) -> list:
        """Run the real rule over records: stores snapshots (scored once a model exists)."""

        return self.rule().analyze(records, self.db)

    def snapshot_count(self) -> int:
        return count_feature_snapshots(self.db, feature_set=self.feature_set, entity_type=self.spec.entity_type)

    def train(self, *, random_state: int = 42):
        trainer = importlib.import_module(self.spec.train_module).train
        model = trainer(self.db, min_samples=self.spec.min_samples, random_state=random_state)
        self.db.flush()
        self.trained = True
        return model

    def latest_scores(self) -> dict[str, float | None]:
        """entity_id -> score of its most recent snapshot (oldest-first order, last write wins)."""

        latest: dict[str, float | None] = {}
        for snapshot in list_feature_snapshots(self.db, feature_set=self.feature_set, entity_type=self.spec.entity_type):
            latest[snapshot.entity_id] = snapshot.score
        return latest


@contextmanager
def isolated_scenario(db: Session, key: str, label: str = "") -> Iterator[Scenario]:
    """A scenario with its own feature-set name, restored globals, and rolled-back DB changes."""

    spec = SPECS[key]
    rule_mod = importlib.import_module(spec.rule_module)
    train_mod = importlib.import_module(spec.train_module)
    original_rule_name, original_train_name = rule_mod.FEATURE_SET, train_mod.FEATURE_SET

    name = f"anomeval-{key}-{label or 'run'}-{uuid4().hex[:8]}"
    savepoint = db.begin_nested()
    rule_mod.FEATURE_SET = name
    train_mod.FEATURE_SET = name
    try:
        yield Scenario(spec=spec, feature_set=name, db=db)
    finally:
        rule_mod.FEATURE_SET = original_rule_name
        train_mod.FEATURE_SET = original_train_name
        if savepoint.is_active:
            savepoint.rollback()
