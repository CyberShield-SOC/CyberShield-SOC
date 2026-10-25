"""Collector authentication, validation, provenance, and pipeline regressions."""
from types import SimpleNamespace
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import select

from app.db.session import get_db
from app.main import app
from app.models.role import Role
from app.models.user import User
from app.schemas.ingestion import IngestionRequest
from app.security import current_user, mint_access_token

pytestmark = pytest.mark.no_db


@pytest.fixture
def client():
    previous = dict(app.dependency_overrides)
    app.dependency_overrides[get_db] = lambda: MagicMock()
    with TestClient(app) as client:
        yield client
    app.dependency_overrides.clear()
    app.dependency_overrides.update(previous)


def request_body(**overrides):
    return {"source_name": "auth-collector", "source_host": "web-01", "source_type": "agent",
            "filename": "auth.log", "content": "Jun 14 14:00:00 web-01 useradd[1]: new user: name=mallory, UID=2001", **overrides}


@pytest.mark.parametrize("path", ["/ingest", "/api/ingest"])
def test_ingestion_requires_authentication(client, path):
    assert client.post(path, json=request_body()).status_code == 401


@pytest.mark.parametrize("role", ["Viewer", "SuperUser"])
def test_ingestion_rejects_read_only_and_unknown_roles(client, role):
    app.dependency_overrides[current_user] = lambda: SimpleNamespace(role=SimpleNamespace(name=role))
    assert client.post("/api/ingest", json=request_body()).status_code == 403


@pytest.mark.parametrize("role", ["Admin", "Analyst"])
def test_ingestion_passes_provenance_to_shared_pipeline(client, monkeypatch, role):
    app.dependency_overrides[current_user] = lambda: SimpleNamespace(id=42, role=SimpleNamespace(name=role))
    pipeline = MagicMock(return_value={"success": True})
    monkeypatch.setattr("app.routers.upload._run_upload_pipeline", pipeline)
    response = client.post("/api/ingest", json=request_body(filename="../../auth.log"))
    assert response.status_code == 200
    kwargs = pipeline.call_args.kwargs
    assert kwargs["source_filename"] == "auth.log"
    assert kwargs["source_name"] == "auth-collector"
    assert kwargs["source_host"] == "web-01"
    assert kwargs["source_type"] == "agent"
    assert kwargs["ingested_by"] == 42


@pytest.mark.parametrize("overrides", [{"source_name": "  "}, {"source_host": "bad\nhost"},
    {"source_type": "unknown"}, {"content": ""}, {"ingested_by": 999}])
def test_ingestion_rejects_invalid_or_forged_metadata(overrides):
    with pytest.raises(ValidationError):
        IngestionRequest(**request_body(**overrides))


def test_access_token_uses_current_database_role(client):
    user = User(id=42, username="review", role=Role(name="Admin"), is_active=True)
    token, _ = mint_access_token(user)
    user.role = Role(name="Viewer")
    db = MagicMock()
    db.scalar.return_value = user
    app.dependency_overrides[get_db] = lambda: db
    assert client.post("/ingest", json=request_body(), headers={"Authorization": f"Bearer {token}"}).status_code == 403
    user.is_active = False
    assert client.post("/ingest", json=request_body(), headers={"Authorization": f"Bearer {token}"}).status_code == 401


@pytest.mark.parametrize("filename,content,status", [
    ("events.exe", "text", 415), ("events.log", "\x00binary", 415),
    ("events.log", "   ", 400),
])
def test_invalid_collector_content_never_reaches_pipeline(client, monkeypatch, filename, content, status):
    app.dependency_overrides[current_user] = lambda: SimpleNamespace(id=42, role=SimpleNamespace(name="Admin"))
    pipeline = MagicMock()
    monkeypatch.setattr("app.routers.upload._run_upload_pipeline", pipeline)
    assert client.post("/ingest", json=request_body(filename=filename, content=content)).status_code == status
    pipeline.assert_not_called()


def test_pipeline_rolls_back_non_database_failures(monkeypatch):
    from app.routers.upload import _run_upload_pipeline

    db = MagicMock()
    monkeypatch.setattr("app.routers.upload.parse_log", lambda *_: {
        "format": "syslog", "total_lines": 1, "entries": [{}], "skipped_lines": [],
    })
    monkeypatch.setattr("app.routers.upload.create_upload_batch", MagicMock(side_effect=RuntimeError("pipeline failed")))
    with pytest.raises(RuntimeError, match="pipeline failed"):
        _run_upload_pipeline(db, content_bytes=b"event", source_filename="events.log", mime_type="text/plain")
    db.rollback.assert_called_once()
    db.commit.assert_not_called()


@pytest.mark.db
def test_collector_persists_metadata_logs_and_detection(db_session):
    # This uses the real pipeline and rollback-only PostgreSQL fixture.
    role = db_session.scalar(select(Role).where(Role.name == "Admin"))
    if role is None:
        role = Role(name="Admin")
        db_session.add(role)
        db_session.flush()
    suffix = uuid4().hex
    user = User(username=f"collector_{suffix}", email=f"{suffix}@example.test",
                role_id=role.id, password_hash="unused", is_active=True)
    db_session.add(user)
    db_session.flush()
    token, _ = mint_access_token(user)
    with TestClient(app, headers={"Authorization": f"Bearer {token}"}) as api:
        host = f"h{suffix[:10]}"
        response = api.post("/api/ingest", json=request_body(source_host=host,
            content=f"Jun 14 14:00:00 {host} useradd[1]: new user: name=mallory, UID=2001"))
        assert response.status_code == 200, response.text
        result = response.json()
        assert result["upload"]["source_host"] == host
        assert result["upload"]["ingested_by"] == user.id
        assert result["parsing"]["stored_entries"] == 1
        assert "new_account_created" in {alert["rule"] for alert in result["alerts"]}
        batch = api.get(f"/api/upload/batches/{result['upload']['upload_id']}").json()
        assert len(batch["logs"]) == 1
        assert batch["upload"]["source_name"] == "auth-collector"
