"""Two scenarios in one session must not share state through the FEATURE_SET globals.

The rules and the training modules read a module-level FEATURE_SET, and a model
trains on "every snapshot stored under that name". If a scenario leaked its name
(or its rows), a later scenario would silently train on, or be scored against,
the earlier one's data. These tests prove the harness prevents that, and a
negative control shows the leak is real without it.
"""

from __future__ import annotations

import importlib
import random
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app.detection.models import LogRecord
from app.repositories.ml_repository import count_feature_snapshots, get_active_model, list_feature_snapshots, list_models
from tests.anomaly_eval.harness import SPECS, isolated_scenario

BASE = datetime(2026, 1, 5, tzinfo=timezone.utc)


def login_records(users: list[str], count: int, *, seed: int = 1, country: str = "US") -> list[LogRecord]:
    """`count` successful logins spread over `users`, with real variance in time of day."""

    rng = random.Random(seed)
    return [
        LogRecord(
            line_number=i,
            timestamp=BASE.replace(hour=rng.randint(7, 18), minute=rng.randint(0, 59)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            ip_address="10.0.0.9",
            username=users[i % len(users)],
            event_type="login_attempt",
            status="SUCCESS",
            country=country,
        )
        for i in range(count)
    ]


def globals_of(key: str) -> tuple[str, str]:
    spec = SPECS[key]
    return (
        importlib.import_module(spec.rule_module).FEATURE_SET,
        importlib.import_module(spec.train_module).FEATURE_SET,
    )


@pytest.mark.parametrize("key", sorted(SPECS))
def test_globals_are_restored_when_a_scenario_ends(db_session, key):
    before = globals_of(key)
    with isolated_scenario(db_session, key) as scenario:
        assert scenario.feature_set not in before
    assert globals_of(key) == before


@pytest.mark.parametrize("key", sorted(SPECS))
def test_globals_are_restored_even_when_the_scenario_raises(db_session, key):
    before = globals_of(key)
    with pytest.raises(RuntimeError, match="boom"):
        with isolated_scenario(db_session, key):
            raise RuntimeError("boom")
    assert globals_of(key) == before


def test_the_unique_name_is_bound_in_both_modules_while_active(db_session):
    with isolated_scenario(db_session, "login", label="one") as first:
        assert globals_of("login") == (first.feature_set, first.feature_set)
    with isolated_scenario(db_session, "login", label="one") as second:
        assert globals_of("login") == (second.feature_set, second.feature_set)
    assert first.feature_set != second.feature_set, "even identical labels must not reuse a name"


def test_sequential_scenarios_in_one_session_do_not_share_snapshots_or_models(db_session):
    with isolated_scenario(db_session, "login", label="a") as a:
        a.ingest(login_records([f"a-user-{i}" for i in range(10)], 60))
        assert a.snapshot_count() == 60
        model_a = a.train()
        assert get_active_model(db_session, feature_set=a.feature_set, entity_type="account") is not None
        name_a = a.feature_set

    # A is over: its rows and its model are gone, and the globals are back.
    assert count_feature_snapshots(db_session, feature_set=name_a, entity_type="account") == 0
    assert list_models(db_session, feature_set=name_a) == []

    with isolated_scenario(db_session, "login", label="b") as b:
        assert b.snapshot_count() == 0, "B started with A's snapshots"
        assert get_active_model(db_session, feature_set=b.feature_set, entity_type="account") is None, "B inherited A's model"
        b.ingest(login_records([f"b-user-{i}" for i in range(10)], 55, seed=2))
        assert b.snapshot_count() == 55, "B's training pool must be exactly B's data, not A+B"
        model_b = b.train()
        assert model_b.sample_count == 55 and model_a.sample_count == 60
        assert model_b.id != model_a.id


def test_a_nested_scenario_does_not_disturb_the_outer_one(db_session):
    with isolated_scenario(db_session, "login", label="outer") as outer:
        outer.ingest(login_records(["outer-user"], 5))
        outer_name = outer.feature_set

        with isolated_scenario(db_session, "login", label="inner") as inner:
            inner.ingest(login_records(["inner-user"], 3))
            assert globals_of("login") == (inner.feature_set, inner.feature_set)
            assert inner.snapshot_count() == 3

        # Inner is over: the outer name is bound again, and outer's data is intact.
        assert globals_of("login") == (outer_name, outer_name)
        outer.ingest(login_records(["outer-user"], 2, seed=3))
        assert outer.snapshot_count() == 7
        assert {s.entity_id for s in list_feature_snapshots(db_session, feature_set=outer_name, entity_type="account")} == {"outer-user"}


def test_entity_baselines_do_not_leak_between_scenarios(db_session):
    """The login rule remembers each account's known countries in entity_baselines,
    which is NOT keyed by feature set. Only the savepoint rollback keeps it clean."""

    def first_is_new_geo(scenario) -> float:
        return list_feature_snapshots(db_session, feature_set=scenario.feature_set, entity_type="account")[0].features["is_new_geo"]

    with isolated_scenario(db_session, "login", label="a") as a:
        a.ingest(login_records(["same-user"], 1, country="US"))
        assert first_is_new_geo(a) == 1.0  # first sighting of US for this account

    with isolated_scenario(db_session, "login", label="b") as b:
        b.ingest(login_records(["same-user"], 1, country="US"))
        assert first_is_new_geo(b) == 1.0, "A's remembered country leaked into B"


def test_negative_control_without_isolation_state_does_leak(db_session, monkeypatch):
    """Proves the tests above are not vacuous: with a shared, hand-set name and no
    savepoint, the second 'scenario' trains on the first one's snapshots."""

    spec = SPECS["login"]
    rule_mod = importlib.import_module(spec.rule_module)
    train_mod = importlib.import_module(spec.train_module)
    monkeypatch.setattr(rule_mod, "FEATURE_SET", "anomeval-shared-name")
    monkeypatch.setattr(train_mod, "FEATURE_SET", "anomeval-shared-name")

    rule = spec.rule_cls()()
    rule.analyze(login_records([f"x-{i}" for i in range(10)], 60), db_session)  # "scenario A"
    rule.analyze(login_records([f"y-{i}" for i in range(10)], 55, seed=2), db_session)  # "scenario B"

    leaked = count_feature_snapshots(db_session, feature_set="anomeval-shared-name", entity_type="account")
    assert leaked == 115, "without isolation B's pool is A+B, the contamination the harness prevents"
