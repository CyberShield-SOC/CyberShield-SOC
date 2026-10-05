"""PT-03: exact evidence, pagination, durable rows, and authorization."""
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError

from app.main import app
from app.models.alert import Alert
from app.models.correlation import CorrelationGroup, CorrelationGroupEvent
from app.models.log import Log
from app.models.role import Role
from app.models.upload_batch import UploadBatch
from app.models.user import User
from app.security import current_user
from app.routers import upload


@pytest.fixture
def api_user(db_session):
    role = db_session.scalar(select(Role).where(Role.name == "Analyst"))
    suffix = uuid4().hex
    user = User(role_id=role.id, username=suffix, email=f"{suffix}@example.test", password_hash="unused")
    db_session.add(user)
    db_session.commit()
    app.dependency_overrides[current_user] = lambda: user
    yield user
    app.dependency_overrides.pop(current_user, None)


def upload_burst(client):
    # The generic parser uses CSV for an explicit, reproducible schema.
    content = "timestamp,ip_address,username,event_type,status\n" + "\n".join(
        f"2026-01-01T12:00:0{i}Z,192.0.2.10,admin,login_attempt,FAILED" for i in range(5)
    ) + "\n2026-01-01T12:00:02Z,192.0.2.99,other,login_attempt,SUCCESS\n"
    response = client.post("/api/upload", files={"logfile": ("burst.csv", content.encode(), "text/csv")})
    assert response.status_code == 200, response.text
    return response.json()


def test_evidence_groups_pagination_and_fresh_session(api_user, test_session_factory):
    with TestClient(app) as client:
        result = upload_burst(client)
        alert = next(a for a in result["alerts"] if a["rule"] == "brute_force_login")
        groups = client.get(f"/api/alerts/{alert['id']}/correlation-groups").json()["groups"]
        assert groups
        identity = groups[0]["id"]
        assert groups[0]["counts"]["events"] == 5
        page = client.get(f"/correlation-groups/{identity}/events?page_size=2").json()
        assert page["pagination"]["total"] == 5
        assert len(page["events"]) == 2
        later = client.get(f"/correlation-groups/{identity}/events?page_size=2&page=2").json()
        assert not {e["id"] for e in page["events"]} & {e["id"] for e in later["events"]}
        evidence = client.get(f"/alerts/{alert['id']}/evidence").json()
        assert evidence["completeness"]["complete"]
        assert all(e["normalized"]["ip_address"] == "192.0.2.10" for e in evidence["events"])
        context = client.get(f"/correlation-groups/{identity}/rule-context").json()
        assert context["rule_context"]["policy"]["rule_key"] == alert["rule"]
        assert client.get(f"/correlation-groups/{identity}/alerts").json()["pagination"]["total"] >= 1
        assert client.get(f"/correlation-groups/{identity}/uploads").json()["pagination"]["total"] == 1
        client.post("/upload", files={"logfile": ("later.csv", b"timestamp,ip_address,username,event_type,status\n2026-01-02T12:00:00Z,192.0.2.88,later,login_attempt,SUCCESS\n", "text/csv")})
        assert client.get(f"/alerts/{alert['id']}/evidence").json()["events"] == evidence["events"]
    with test_session_factory() as fresh:
        assert fresh.get(CorrelationGroup, identity)
        assert fresh.scalar(select(func.count()).select_from(CorrelationGroupEvent).where(CorrelationGroupEvent.group_id == identity)) == 5


def test_read_permissions_missing_and_bad_filters(api_user):
    with TestClient(app) as client:
        assert client.get("/correlation-groups/999999999").status_code == 404
        assert client.get("/alerts/999999999/evidence").status_code == 404
        assert client.get("/correlation-groups?page_size=101").status_code == 422
        assert client.get("/correlation-groups?start=2026-01-02T00:00:00&end=2026-01-01T00:00:00Z").status_code == 422
        api_user.role = Role(name="Viewer")
        assert client.get("/correlation-groups").status_code == 200
        assert client.post("/upload", files={"logfile": ("x.csv", b"data", "text/csv")}).status_code == 403
        api_user.role = Role(name="Unsupported")
        assert client.get("/correlation-groups").status_code == 403
        app.dependency_overrides.pop(current_user)
        assert client.get("/correlation-groups").status_code == 401


def test_failed_correlation_rolls_back_entire_upload(api_user, db_session, monkeypatch):
    before = {model: db_session.scalar(select(func.count()).select_from(model)) for model in (Log, Alert, UploadBatch, CorrelationGroup)}
    def fail(*args, **kwargs):
        raise SQLAlchemyError("synthetic persistence failure")
    monkeypatch.setattr(upload, "correlate_upload", fail)
    with TestClient(app) as client:
        content = b"timestamp,ip_address,username,event_type,status\n2026-01-01T00:00:00Z,192.0.2.10,admin,login_attempt,FAILED\n"
        assert client.post("/upload", files={"logfile": ("rollback.csv", content, "text/csv")}).status_code == 500
    assert {model: db_session.scalar(select(func.count()).select_from(model)) for model in before} == before


def test_lateral_chain_retains_exact_prior_upload_evidence(api_user):
    with TestClient(app) as client:
        def send(hosts, offset):
            content = "timestamp,ip_address,username,hostname,event_type,status\n" + "\n".join(
                f"2026-01-01T12:00:{offset+i:02d}Z,192.0.2.10,pivot,{host},login_attempt,SUCCESS" for i, host in enumerate(hosts)
            )
            response = client.post("/upload", files={"logfile": ("chain.csv", content.encode(), "text/csv")})
            assert response.status_code == 200
            return response.json()
        first = send(["host-a", "host-b"], 0)
        second = send(["host-c"], 2)
        alert = next(a for a in second["alerts"] if a["rule"] == "lateral_movement_chain")
        source = client.get(f"/alerts/{alert['id']}/evidence").json()
        assert source["completeness"]["complete"]
        assert source["pagination"]["total"] == 3
        assert {e["upload_id"] for e in source["events"]} == {first["upload"]["upload_id"], second["upload"]["upload_id"]}
        group = client.get(f"/alerts/{alert['id']}/correlation-groups").json()["groups"][0]
        assert group["counts"] == {"events": 3, "alerts": 1, "uploads": 2}


def test_replayed_persistence_does_not_duplicate_groups_or_links(api_user, db_session):
    from app.models.correlation import CorrelationGroupAlert, CorrelationGroupUpload
    from app.repositories.correlation_repository import save_results
    from app.services.correlation import CorrelationResult
    with TestClient(app) as client:
        upload_burst(client)
    group = db_session.scalar(select(CorrelationGroup).order_by(CorrelationGroup.id))
    fields = ("fingerprint", "group_type", "entity_type", "entity_value", "first_seen", "last_seen", "window_seconds", "severity", "confidence", "reason", "rule_key", "rule_context")
    result = CorrelationResult(**{field: getattr(group, field) for field in fields},
        event_ids=tuple(db_session.scalars(select(CorrelationGroupEvent.log_id).where(CorrelationGroupEvent.group_id == group.id))),
        alert_ids=tuple(db_session.scalars(select(CorrelationGroupAlert.alert_id).where(CorrelationGroupAlert.group_id == group.id))),
        upload_ids=tuple(str(value) for value in db_session.scalars(select(CorrelationGroupUpload.upload_id).where(CorrelationGroupUpload.group_id == group.id))))
    models = (CorrelationGroup, CorrelationGroupEvent, CorrelationGroupAlert, CorrelationGroupUpload)
    before = [db_session.scalar(select(func.count()).select_from(model)) for model in models]
    assert save_results(db_session, [result, result])[0].id == group.id
    assert [db_session.scalar(select(func.count()).select_from(model)) for model in models] == before
