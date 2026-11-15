"""S7-02.5: watched-directory collector -> /api/ingest -> real parser, normalization,
detection, correlation and alert storage on PostgreSQL.

The collector talks to the FastAPI app in-process through a transport adapter,
so these tests exercise the real auth middleware (refresh + CSRF double submit),
ingestion route, pipeline and upload history used for reconciliation.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.main import app
from app.models.alert import Alert
from app.models.log import Log
from app.models.role import Role
from app.models.upload_batch import UploadBatch
from app.models.user import User
from app.security import create_refresh_token

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "collector"))

from cybershield_collector.api import CyberShieldClient, HttpResponse, TransportError  # noqa: E402
from cybershield_collector.config import parse_config  # noqa: E402
from cybershield_collector.watcher import Collector  # noqa: E402

pytestmark = pytest.mark.db

RULE_TESTS = REPO / "sample-logs" / "cybershield-rule-tests"


class AppTransport:
    """Routes collector HTTP calls into the FastAPI app (no cookie jar carry-over)."""

    def __init__(self):
        self.client = TestClient(app, base_url="http://soc.test")
        self.after_ingest = None  # optional hook simulating a lost response

    def __call__(self, method, url, headers, body, timeout):
        self.client.cookies.clear()
        response = self.client.request(method, url, headers=headers, content=body)
        result = HttpResponse(response.status_code, list(response.headers.multi_items()), response.content)
        if url.split("?")[0].endswith("/ingest") and self.after_ingest:
            hook, self.after_ingest = self.after_ingest, None
            hook(result)
        return result


@pytest.fixture
def collector_env(db_session, tmp_path, monkeypatch):
    monkeypatch.delenv("CYBERSHIELD_ACCESS_TOKEN", raising=False)
    monkeypatch.delenv("CYBERSHIELD_API_URL", raising=False)
    role = db_session.scalar(select(Role).where(Role.name == "Analyst"))
    if role is None:
        role = Role(name="Analyst")
        db_session.add(role)
        db_session.flush()
    suffix = uuid4().hex
    user = User(username=f"collector_{suffix[:12]}", email=f"{suffix}@example.test",
                role_id=role.id, password_hash="unused", is_active=True)
    db_session.add(user)
    db_session.flush()
    refresh_token = create_refresh_token(db_session, user, ttl_minutes=7 * 24 * 60)

    watched = tmp_path / "watched"
    watched.mkdir()
    host = f"host-{suffix[:10]}"
    config = parse_config({
        "api_url": "http://soc.test/api", "state_dir": str(tmp_path / "state"),
        "source_host": host, "settle_seconds": 0,
        "sources": [{"name": "auth-watch", "path": str(watched)}],
    })
    config.state_dir.mkdir()
    config.session_file.write_text(json.dumps({"api_url": config.api_url, "refresh_token": refresh_token}))
    transport = AppTransport()

    def make_collector():
        return Collector(config, CyberShieldClient(config, transport=transport), sleep=lambda s: None)

    class Env:
        pass

    env = Env()
    env.db, env.user, env.host, env.dir, env.config = db_session, user, host, watched, config
    env.transport, env.make, env.original_refresh = transport, make_collector, refresh_token

    def batches():
        return list(db_session.scalars(select(UploadBatch).where(UploadBatch.source_host == host)
                                       .order_by(UploadBatch.uploaded_at)).all())

    def logs():
        ids = [b.upload_id for b in batches()]
        return list(db_session.scalars(select(Log).where(Log.upload_id.in_(ids))
                                       .order_by(Log.upload_id, Log.line_number)).all()) if ids else []

    def alert_rules():
        ids = [b.upload_id for b in batches()]
        return {a.rule for a in db_session.scalars(select(Alert).where(Alert.upload_id.in_(ids))).all()} if ids else set()

    env.batches, env.logs, env.alert_rules = batches, logs, alert_rules
    yield env
    env.transport.client.close()


def _age(path: Path):
    past = os.stat(path).st_mtime - 60
    os.utime(path, (past, past))


def test_collected_file_flows_through_parser_detection_and_alerts(collector_env):
    env = collector_env
    shutil.copy(RULE_TESTS / "04_all_rules_combined.log", env.dir / "auth.log")
    _age(env.dir / "auth.log")

    stats = env.make().scan_once()

    (batch,) = env.batches()
    assert (batch.source_name, batch.source_type, batch.source_host) == ("auth-watch", "agent", env.host)
    assert batch.ingested_by == env.user.id
    assert batch.source_filename == "auth.log" and batch.source_format == "syslog"
    logs = env.logs()
    assert len(logs) == 12 == batch.stored_entries
    # Normalization: structured fields extracted from raw syslog lines.
    assert any(log.ip_address is not None and log.username and log.event_type for log in logs)
    # Detection: the README's expected alerts for this fixture, from the same engine as /upload.
    assert {"brute_force_login", "invalid_user_enumeration", "sudo_failure"} <= env.alert_rules()
    assert stats["stored_alerts"] == batch.stored_alerts >= 3


def test_no_alert_control_file_raises_no_threat_alerts(collector_env):
    env = collector_env
    shutil.copy(RULE_TESTS / "05_no_alert_control.log", env.dir / "control.log")
    _age(env.dir / "control.log")
    env.make().scan_once()
    assert len(env.batches()) == 1
    assert not {"brute_force_login", "invalid_user_enumeration", "sudo_failure"} & env.alert_rules()


def test_rescans_appends_and_rotation_never_duplicate_stored_logs(collector_env):
    env = collector_env
    log_path = env.dir / "auth.log"
    shutil.copy(RULE_TESTS / "01_brute_force_login.log", log_path)
    _age(log_path)
    collector = env.make()
    collector.scan_once()
    collector.scan_once()
    assert len(env.batches()) == 1

    extra = "Oct 25 10:15:00 web-01 sshd[999]: Accepted password for alice from 192.0.2.10 port 51000 ssh2\n"
    with open(log_path, "a", encoding="utf-8") as handle:
        handle.write(extra)
    _age(log_path)
    collector.scan_once()
    assert len(env.batches()) == 2
    assert [log.raw_message for log in env.logs() if log.upload_id == env.batches()[-1].upload_id] == [extra.strip()]

    os.rename(log_path, env.dir / "auth.log.1")  # logrotate
    env.make().scan_once()  # and a collector restart
    raw = [log.raw_message for log in env.logs()]
    assert len(env.batches()) == 2 and len(raw) == len(set(raw)) == 6


def test_real_refresh_flow_rotates_and_persists_session(collector_env):
    env = collector_env
    shutil.copy(RULE_TESTS / "03_sudo_failure.log", env.dir / "auth.log")
    _age(env.dir / "auth.log")
    env.make().scan_once()
    saved = json.loads(env.config.session_file.read_text())
    assert saved["refresh_token"] != env.original_refresh  # rotated by /auth/refresh and saved
    assert len(env.batches()) == 1
    env.make().scan_once()  # a restarted collector authenticates with the rotated token
    assert "password" not in json.dumps(saved).lower()


def test_lost_response_is_reconciled_with_upload_history_not_resent(collector_env):
    env = collector_env
    shutil.copy(RULE_TESTS / "02_username_enumeration.log", env.dir / "auth.log")
    _age(env.dir / "auth.log")

    def lose_response(_result):
        raise TransportError("read timed out", maybe_delivered=True)

    env.transport.after_ingest = lose_response  # server commits, collector never hears back
    collector = env.make()
    collector.scan_once()
    collector.retry_at = 0
    collector.scan_once()
    assert len(env.batches()) == 1
    assert collector.stats["reconciled"] == 1
    assert next(iter(collector.store.records.values())).last_upload_id == str(env.batches()[0].upload_id)
