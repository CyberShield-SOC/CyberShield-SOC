"""ML model lifecycle API: list/train/activate and the shadow-mode scores review queue."""

from __future__ import annotations

import random
import sys
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.main import app
from app.ml.features import login_behavior_features
from app.models.role import Role
from app.models.user import User
from app.repositories.ml_repository import save_feature_snapshot
from app.security import current_user

client = TestClient(app)
BASE = datetime(2026, 9, 10, tzinfo=timezone.utc)


def as_role(db_session, role_name: str) -> User:
    role = db_session.scalar(select(Role).where(Role.name == role_name))
    if role is None:
        role = Role(name=role_name, description=role_name)
        db_session.add(role)
        db_session.flush()
    user = User(
        role_id=role.id, username=f"ml-{uuid4().hex[:8]}", email=f"ml-{uuid4().hex[:8]}@example.test",
        password_hash="x", is_active=True,
    )
    user.role = role
    db_session.add(user)
    db_session.commit()
    app.dependency_overrides[current_user] = lambda: user
    return user


@pytest.fixture(autouse=True)
def reset_overrides():
    yield
    app.dependency_overrides.pop(current_user, None)


def _seed_snapshots(db_session, feature_set: str, count: int = 60) -> None:
    rng = random.Random(7)
    for i in range(count):
        hour = 9 + rng.uniform(-1.0, 1.0)
        ts = BASE.replace(hour=int(hour) % 24, minute=int((hour % 1) * 60))
        save_feature_snapshot(
            db_session, feature_set=feature_set, entity_type="account", entity_id=f"user{i % 5}",
            captured_at=ts, features=login_behavior_features(ts, is_new_geo=False),
        )
    db_session.commit()


def _register_throwaway_feature_set(monkeypatch) -> str:
    # A fresh, random feature_set per test — never the real "login_behavior"
    # etc. — so seeded snapshots can't mix with (or be miscounted against)
    # whatever real training history already exists in this database.
    # train_login_behavior.FEATURE_SET must also be patched: train()
    # reads that module global directly, so without this the trainer
    # would save under the real "login_behavior" name regardless of
    # which feature_set the request/registry entry uses. The pilot borrows
    # the login rule's live params (threshold -0.02, shadow mode on).
    feature_set = f"pytest-{uuid4().hex[:8]}"
    monkeypatch.setattr("app.ml.train_login_behavior.FEATURE_SET", feature_set)
    import app.ml.registry as registry_module
    from app.ml.train_login_behavior import train as login_train

    monkeypatch.setitem(registry_module.TRAINERS, feature_set, login_train)
    monkeypatch.setitem(
        registry_module.TRAINER_META, feature_set,
        {"entity_type": "account", "min_samples": 50, "rule_name": "behavioral_anomaly_login"},
    )
    return feature_set


def test_train_requires_admin(db_session):
    as_role(db_session, "Analyst")
    response = client.post("/ml/models/login_behavior/train")
    assert response.status_code == 403


def test_train_unknown_feature_set_is_404(db_session):
    as_role(db_session, "Admin")
    response = client.post("/ml/models/not-a-real-feature-set/train")
    assert response.status_code == 404


def test_train_with_insufficient_data_is_422(db_session, monkeypatch):
    as_role(db_session, "Admin")
    feature_set = _register_throwaway_feature_set(monkeypatch)

    response = client.post(f"/ml/models/{feature_set}/train")
    assert response.status_code == 422


def test_train_list_and_activate_round_trip(db_session, monkeypatch):
    feature_set = _register_throwaway_feature_set(monkeypatch)

    as_role(db_session, "Admin")
    _seed_snapshots(db_session, feature_set)

    trained = client.post(f"/ml/models/{feature_set}/train")
    assert trained.status_code == 200, trained.text
    first_model = trained.json()["model"]
    assert first_model["feature_set"] == feature_set
    assert first_model["version"] == 1
    assert first_model["is_active"] is True
    assert first_model["sample_count"] == 60

    listed = client.get("/ml/models", params={"feature_set": feature_set})
    assert listed.status_code == 200
    assert len(listed.json()["models"]) == 1

    _seed_snapshots(db_session, feature_set, count=10)
    retrained = client.post(f"/ml/models/{feature_set}/train")
    second_model = retrained.json()["model"]
    assert second_model["version"] == 2
    assert second_model["is_active"] is True

    listed_again = client.get("/ml/models", params={"feature_set": feature_set}).json()["models"]
    versions = {m["version"]: m["is_active"] for m in listed_again}
    assert versions == {1: False, 2: True}

    rolled_back = client.post(f"/ml/models/{first_model['id']}/activate")
    assert rolled_back.status_code == 200
    assert rolled_back.json()["model"]["version"] == 1

    final_state = {m["version"]: m["is_active"] for m in client.get("/ml/models", params={"feature_set": feature_set}).json()["models"]}
    assert final_state == {1: True, 2: False}


def test_activate_unknown_model_is_404(db_session):
    as_role(db_session, "Admin")
    response = client.post("/ml/models/999999999/activate")
    assert response.status_code == 404


def test_list_models_open_to_viewer(db_session):
    as_role(db_session, "Viewer")
    response = client.get("/ml/models")
    assert response.status_code == 200


class TestScoresReviewQueue:
    def test_viewer_can_read_scores(self, db_session):
        # Read-only: every role may see what shadow mode is finding.
        as_role(db_session, "Viewer")
        response = client.get("/ml/scores", params={"feature_set": "login_behavior"})
        assert response.status_code == 200

    def test_analyst_sees_lowest_scores_first(self, db_session):
        as_role(db_session, "Analyst")
        feature_set = f"pytest-{uuid4().hex[:8]}"
        ts = BASE.replace(hour=9)
        save_feature_snapshot(
            db_session, feature_set=feature_set, entity_type="account", entity_id="u1",
            captured_at=ts, features=login_behavior_features(ts, is_new_geo=False), score=0.15,
        )
        save_feature_snapshot(
            db_session, feature_set=feature_set, entity_type="account", entity_id="u2",
            captured_at=ts, features=login_behavior_features(ts, is_new_geo=True), score=-0.30,
        )
        save_feature_snapshot(
            db_session, feature_set=feature_set, entity_type="account", entity_id="u3",
            captured_at=ts, features=login_behavior_features(ts, is_new_geo=False), score=None,
        )
        db_session.commit()

        response = client.get("/ml/scores", params={"feature_set": feature_set, "entity_type": "account"})
        assert response.status_code == 200
        rows = response.json()["scores"]
        assert [r["entity_id"] for r in rows] == ["u2", "u1"]

        filtered = client.get(
            "/ml/scores", params={"feature_set": feature_set, "entity_type": "account", "below": 0.0}
        ).json()["scores"]
        assert [r["entity_id"] for r in filtered] == ["u2"]


class TestAnomalyOverview:
    def test_every_registered_pilot_maps_to_a_real_rule(self):
        from app.ml.registry import TRAINER_META, TRAINERS
        from app.repositories.detection_rule_setting_repository import known_rule_names

        assert set(TRAINER_META) == set(TRAINERS)
        assert {meta["rule_name"] for meta in TRAINER_META.values()} <= known_rule_names()

    def test_open_to_viewer_with_rule_params_and_progress(self, db_session):
        as_role(db_session, "Viewer")
        response = client.get("/ml/anomalies")
        assert response.status_code == 200
        pilots = {row["feature_set"]: row for row in response.json()["pilots"]}
        assert set(pilots) == {"login_behavior", "egress_volume", "threat_log"}
        login = pilots["login_behavior"]
        assert login["rule_name"] == "behavioral_anomaly_login"
        assert login["entity_type"] == "account"
        assert login["min_samples"] == 50
        assert login["score_threshold"] == -0.02
        assert isinstance(login["shadow_mode"], bool)
        assert isinstance(login["scores"], list)

    def test_reports_progress_below_floor_and_no_active_model(self, db_session, monkeypatch):
        as_role(db_session, "Admin")
        feature_set = _register_throwaway_feature_set(monkeypatch)
        _seed_snapshots(db_session, feature_set, count=12)

        pilots = {row["feature_set"]: row for row in client.get("/ml/anomalies").json()["pilots"]}
        row = pilots[feature_set]
        assert row["min_samples"] == 50
        assert row["sample_count"] == 12
        assert row["ready"] is False
        assert row["active_model"] is None
        assert row["scores"] == []

    def test_scored_snapshots_come_with_deviations_and_threshold_flag(self, db_session, monkeypatch):
        as_role(db_session, "Admin")
        feature_set = _register_throwaway_feature_set(monkeypatch)
        _seed_snapshots(db_session, feature_set, count=60)
        trained = client.post(f"/ml/models/{feature_set}/train")
        assert trained.status_code == 200
        model_id = trained.json()["model"]["id"]

        ts = BASE.replace(hour=3)
        save_feature_snapshot(
            db_session, feature_set=feature_set, entity_type="account", entity_id="night-owl",
            captured_at=ts, features=login_behavior_features(ts, is_new_geo=True), score=-0.3, model_id=model_id,
        )
        save_feature_snapshot(
            db_session, feature_set=feature_set, entity_type="account", entity_id="regular",
            captured_at=BASE.replace(hour=9), features=login_behavior_features(BASE.replace(hour=9), is_new_geo=False),
            score=0.1, model_id=model_id,
        )
        db_session.commit()

        pilots = {row["feature_set"]: row for row in client.get("/ml/anomalies", params={"limit": 5}).json()["pilots"]}
        row = pilots[feature_set]
        assert row["active_model"]["version"] == 1
        assert row["sample_count"] == 62
        assert row["scored_count"] == 2
        assert row["shadow_mode"] is True
        assert [s["entity_id"] for s in row["scores"]] == ["night-owl", "regular"]
        flagged, normal = row["scores"]
        assert flagged["below_threshold"] is True
        assert normal["below_threshold"] is False
        assert 1 <= len(flagged["feature_deviations"]) <= 3
        assert {"feature", "value", "z_score"} <= set(flagged["feature_deviations"][0])
        assert isinstance(flagged["id"], int)

    def test_only_the_active_versions_scores_are_listed_and_counted(self, db_session, monkeypatch):
        # Rolling back to v1 must show v1's scores (explained against v1's
        # baseline) and count only them, even though v2's are newer.
        as_role(db_session, "Admin")
        feature_set = _register_throwaway_feature_set(monkeypatch)
        _seed_snapshots(db_session, feature_set, count=60)
        v1 = client.post(f"/ml/models/{feature_set}/train").json()["model"]
        v2 = client.post(f"/ml/models/{feature_set}/train").json()["model"]
        assert (v1["version"], v2["version"]) == (1, 2)

        ts = BASE.replace(hour=3)
        for entity_id, model, score in (("scored-by-v1", v1, -0.2), ("scored-by-v2", v2, -0.4)):
            save_feature_snapshot(
                db_session, feature_set=feature_set, entity_type="account", entity_id=entity_id,
                captured_at=ts, features=login_behavior_features(ts, is_new_geo=True),
                score=score, model_id=model["id"],
            )
        db_session.commit()

        def pilot():
            return {row["feature_set"]: row for row in client.get("/ml/anomalies").json()["pilots"]}[feature_set]

        current = pilot()
        assert current["active_model"]["version"] == 2
        assert current["scored_count"] == 1
        assert [s["entity_id"] for s in current["scores"]] == ["scored-by-v2"]

        assert client.post(f"/ml/models/{v1['id']}/activate").status_code == 200
        rolled_back = pilot()
        assert rolled_back["active_model"]["version"] == 1
        assert rolled_back["scored_count"] == 1
        assert [s["entity_id"] for s in rolled_back["scores"]] == ["scored-by-v1"]
