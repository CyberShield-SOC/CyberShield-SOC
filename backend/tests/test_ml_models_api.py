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
    feature_set = f"pytest-{uuid4().hex[:8]}"
    monkeypatch.setattr("app.ml.train_login_behavior.FEATURE_SET", feature_set)
    import app.ml.registry as registry_module
    from app.ml.train_login_behavior import train as login_train

    monkeypatch.setitem(registry_module.TRAINERS, feature_set, login_train)

    response = client.post(f"/ml/models/{feature_set}/train")
    assert response.status_code == 422


def test_train_list_and_activate_round_trip(db_session, monkeypatch):
    feature_set = f"pytest-{uuid4().hex[:8]}"
    monkeypatch.setattr("app.ml.train_login_behavior.FEATURE_SET", feature_set)
    import app.ml.registry as registry_module
    from app.ml.train_login_behavior import train as login_train

    monkeypatch.setitem(registry_module.TRAINERS, feature_set, login_train)

    admin = as_role(db_session, "Admin")
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
    def test_viewer_cannot_read_scores(self, db_session):
        as_role(db_session, "Viewer")
        response = client.get("/ml/scores", params={"feature_set": "login_behavior"})
        assert response.status_code == 403

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
