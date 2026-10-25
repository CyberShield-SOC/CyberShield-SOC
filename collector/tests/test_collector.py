"""Unit tests for the watched-directory collector against an in-memory fake backend."""
from __future__ import annotations

import json
import os
import shutil
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cybershield_collector.api import CyberShieldClient, HttpResponse, TransportError  # noqa: E402
from cybershield_collector.config import ConfigError, parse_config  # noqa: E402
from cybershield_collector.state import StateStore  # noqa: E402
from cybershield_collector.watcher import Collector, CollectorStopped, upload_filename  # noqa: E402

API = "http://soc.test/api"


class FakeBackend:
    """Just enough of /auth and /ingest to exercise the collector's decisions."""

    def __init__(self):
        self.batches: list[dict] = []
        self.refresh_token = "rt-0"
        self.access_token = "at-0"
        self.fail_next: list = []  # queue of status ints, "refused", or "timeout-after-store"
        self.refresh_calls = 0
        self.expire_access = False

    def __call__(self, method, url, headers, body, timeout):
        parsed = urlparse(url)
        path = parsed.path.removeprefix("/api")
        if path == "/auth/refresh":
            return self._refresh(headers)
        if path == "/auth/login":
            return HttpResponse(200, [("set-cookie", "cybershield_2fa_pending=pend; Path=/; HttpOnly")],
                                json.dumps({"success": True, "email": "k***@example.test"}).encode())
        if path == "/auth/2fa/verify":
            assert "cybershield_2fa_pending=pend" in headers.get("Cookie", "")
            return self._issue()
        if headers.get("Authorization") != f"Bearer {self.access_token}" or self.expire_access:
            self.expire_access = False
            self.access_token = None
            return HttpResponse(401, [], b'{"detail":"Authentication required"}')
        if path == "/ingest":
            return self._ingest(json.loads(body))
        if path == "/upload/history":
            query = parse_qs(parsed.query)["query"][0]
            uploads = [b["upload"] for b in reversed(self.batches) if query in b["upload"]["filename"]]
            return HttpResponse(200, [], json.dumps({"success": True, "uploads": uploads}).encode())
        return HttpResponse(404, [], b"{}")

    def _issue(self):
        self.refresh_token = f"rt-{uuid.uuid4().hex[:6]}"
        self.access_token = f"at-{uuid.uuid4().hex[:6]}"
        return HttpResponse(200, [
            ("set-cookie", f"cybershield_session={self.refresh_token}; HttpOnly; Path=/; SameSite=strict"),
            ("set-cookie", "cybershield_csrf=abc; Path=/"),
        ], json.dumps({"access_token": self.access_token, "expires_in": 600,
                       "user": {"username": "kapil", "role": "Analyst"}}).encode())

    def _refresh(self, headers):
        self.refresh_calls += 1
        cookie = headers.get("Cookie", "")
        csrf_cookie = cookie.split("cybershield_csrf=")[1].split(";")[0]
        assert headers["X-CSRF-Token"] == csrf_cookie  # double-submit pair
        if f"cybershield_session={self.refresh_token}" not in cookie:
            return HttpResponse(401, [], b'{"detail":"Invalid or expired refresh token"}')
        return self._issue()

    def _ingest(self, payload):
        if self.fail_next:
            failure = self.fail_next.pop(0)
            if failure == "refused":
                raise TransportError("refused", maybe_delivered=False)
            if failure == "timeout-before-store":
                raise TransportError("timed out", maybe_delivered=True)
            if failure == "timeout-after-store":
                self._store(payload)
                raise TransportError("timed out", maybe_delivered=True)
            return HttpResponse(failure, [], json.dumps({"detail": {"code": "FAKE"}}).encode())
        lines = [l for l in payload["content"].splitlines() if l.strip()]
        if not lines or all(l.startswith("garbage") for l in lines):
            return HttpResponse(422, [], b'{"detail":{"code":"NO_PARSEABLE_EVENTS"}}')
        return HttpResponse(200, [], json.dumps(self._store(payload)).encode())

    def _store(self, payload):
        lines = [l for l in payload["content"].splitlines() if l.strip()]
        upload = {"upload_id": str(uuid.uuid4()), "filename": payload["filename"],
                  "size_bytes": len(payload["content"].encode()),
                  "uploaded_at": datetime.now(timezone.utc).isoformat(),
                  "source_name": payload["source_name"], "source_type": payload["source_type"],
                  "source_host": payload["source_host"], "stored_entries": len(lines), "stored_alerts": 0}
        result = {"success": True, "upload": upload, "parsing": {"stored_entries": len(lines), "stored_alerts": 0}}
        self.batches.append({"upload": upload, "payload": payload})
        return result

    # helpers
    def lines(self, *, filename: str | None = None, skip_header: str | None = None) -> list[str]:
        out = []
        for batch in self.batches:
            if filename and batch["payload"]["filename"] != filename:
                continue
            out.extend(l for l in batch["payload"]["content"].splitlines()
                       if l.strip() and l != skip_header)
        return out


class Clock:
    def __init__(self):
        self.now = time.time()

    def __call__(self):
        return self.now


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.delenv("CYBERSHIELD_ACCESS_TOKEN", raising=False)
    monkeypatch.delenv("CYBERSHIELD_API_URL", raising=False)
    watched = tmp_path / "watched"
    watched.mkdir()
    backend = FakeBackend()
    clock = Clock()

    def make(**overrides):
        raw = {"api_url": API, "state_dir": str(tmp_path / "state"), "source_host": "web-01",
               "settle_seconds": 0, "poll_interval_seconds": 1,
               "sources": [{"name": "web-01-auth", "path": str(watched), **overrides.pop("source", {})}],
               **overrides}
        config = parse_config(raw, base_dir=tmp_path)
        session = {"api_url": API, "refresh_token": backend.refresh_token}
        config.state_dir.mkdir(parents=True, exist_ok=True)
        if not config.session_file.exists():
            config.session_file.write_text(json.dumps(session))
        client = CyberShieldClient(config, transport=backend, clock=clock)
        collector = Collector(config, client, clock=clock, sleep=lambda s: None)
        return collector

    class Env:
        pass

    e = Env()
    e.dir, e.backend, e.clock, e.make, e.tmp = watched, backend, clock, make, tmp_path
    return e


def write(path: Path, text: str, mode="w"):
    with open(path, mode, encoding="utf-8", newline="") as handle:
        handle.write(text)
    past = os.stat(path).st_mtime - 100
    os.utime(path, (past, past))


SYSLOG = "Oct 25 10:00:0{} web-01 sshd[1]: Failed password for root from 10.0.0.{} port 22 ssh2\n"


# ------------------------------------------------------------------ S7-02.1 collection


def test_new_file_ships_once_with_source_metadata(env):
    write(env.dir / "auth.log", "".join(SYSLOG.format(i, i) for i in range(3)))
    collector = env.make()
    collector.scan_once()
    collector.scan_once()
    assert len(env.backend.batches) == 1
    payload = env.backend.batches[0]["payload"]
    assert payload["source_name"] == "web-01-auth"
    assert payload["source_host"] == "web-01"
    assert payload["source_type"] == "agent"
    assert payload["filename"] == "auth.log"
    assert len(env.backend.lines()) == 3
    ledger = (env.tmp / "state" / "shipments.jsonl").read_text().splitlines()
    assert json.loads(ledger[0])["upload_id"] == env.backend.batches[0]["upload"]["upload_id"]


def test_appended_lines_are_the_only_lines_sent(env):
    log = env.dir / "auth.log"
    write(log, SYSLOG.format(1, 1))
    collector = env.make()
    collector.scan_once()
    write(log, SYSLOG.format(2, 2), mode="a")
    collector.scan_once()
    assert [b["payload"]["content"] for b in env.backend.batches] == [SYSLOG.format(1, 1), SYSLOG.format(2, 2)]


def test_partial_line_waits_for_newline_or_settle(env):
    log = env.dir / "auth.log"
    collector = env.make(settle_seconds=30)
    with open(log, "w") as handle:
        handle.write(SYSLOG.format(1, 1) + "Oct 25 10:00:02 web-01 sshd[1]: Failed")
    env.clock.now = os.stat(log).st_mtime + 1  # still being written
    collector.scan_once()
    assert env.backend.lines() == [SYSLOG.format(1, 1).strip()]
    env.clock.now += 60  # quiet long enough: the tail is final
    collector.scan_once()
    assert env.backend.lines()[-1] == "Oct 25 10:00:02 web-01 sshd[1]: Failed"


def test_only_matching_files_and_never_state_dir(env):
    write(env.dir / "notes.docx", "x\n")
    write(env.dir / "old.log.gz", "x\n")
    write(env.dir / "events.jsonl", '{"event_type":"login"}\n')
    collector = env.make(state_dir=str(env.dir / ".collector"))
    collector.scan_once()
    assert [b["payload"]["filename"] for b in env.backend.batches] == ["events.jsonl"]


def test_csv_header_is_replayed_for_every_chunk(env):
    header = "timestamp,source_ip,username,event_type,status"
    rows = [f"2026-10-25T10:00:{i:02d}Z,10.0.0.{i},u{i},login,failed" for i in range(60)]
    write(env.dir / "signins.csv", header + "\n" + "\n".join(rows) + "\n")
    collector = env.make(max_chunk_bytes=1024)
    collector.scan_once()
    assert len(env.backend.batches) > 1
    for batch in env.backend.batches:
        assert batch["payload"]["content"].splitlines()[0] == header
    assert env.backend.lines(skip_header=header) == rows


def test_header_only_csv_waits_for_rows(env):
    csv_path = env.dir / "signins.csv"
    write(csv_path, "timestamp,source_ip,status\n")
    collector = env.make()
    collector.scan_once()
    assert env.backend.batches == []
    write(csv_path, "2026-10-25T10:00:00Z,10.0.0.1,failed\n", mode="a")
    collector.scan_once()
    assert env.backend.batches[0]["payload"]["content"] == "timestamp,source_ip,status\n2026-10-25T10:00:00Z,10.0.0.1,failed\n"


@pytest.mark.parametrize("name,forced,expected", [
    ("auth.log", None, "auth.log"), ("auth.log.1", None, "auth.log"),
    ("auth.log-20261025", None, "auth.log"), ("messages", None, "messages.log"),
    ("SIGNINS.CSV", None, "SIGNINS.CSV"), ("messages", "txt", "messages.txt"),
])
def test_upload_filename_selects_backend_parser(name, forced, expected):
    assert upload_filename(name, forced) == expected


def test_start_at_end_skips_preexisting_content_only(env):
    write(env.dir / "auth.log", SYSLOG.format(1, 1))
    collector = env.make(source={"start_at": "end"})
    collector.scan_once()
    assert env.backend.batches == []
    write(env.dir / "auth.log", SYSLOG.format(2, 2), mode="a")
    write(env.dir / "new.log", SYSLOG.format(3, 3))
    collector.scan_once()
    assert sorted(env.backend.lines()) == sorted([SYSLOG.format(2, 2).strip(), SYSLOG.format(3, 3).strip()])


# ------------------------------------------------------------------ S7-02.4 deduplication


def test_restart_does_not_resend(env):
    write(env.dir / "auth.log", SYSLOG.format(1, 1))
    env.make().scan_once()
    env.make().scan_once()  # new process, state loaded from disk
    assert len(env.backend.batches) == 1


def test_rotation_by_rename_is_not_resent(env):
    log = env.dir / "auth.log"
    write(log, "".join(SYSLOG.format(i, i) for i in range(5)))
    collector = env.make()
    collector.scan_once()
    write(log, SYSLOG.format(5, 5), mode="a")  # written just before rotation
    os.rename(log, env.dir / "auth.log.1")
    write(log, SYSLOG.format(6, 6))
    collector.scan_once()
    lines = env.backend.lines()
    assert len(lines) == len(set(lines)) == 7
    assert {b["payload"]["filename"] for b in env.backend.batches} == {"auth.log"}


def test_copied_file_is_not_resent_but_its_new_lines_are(env):
    big = "".join(SYSLOG.format(i % 10, i) for i in range(100))  # > 1 KiB: full prefix check
    write(env.dir / "auth.log", big)
    collector = env.make()
    collector.scan_once()
    shutil.copy(env.dir / "auth.log", env.dir / "auth-copy.log")
    collector.scan_once()
    assert len(env.backend.batches) == 1
    write(env.dir / "auth-copy.log", SYSLOG.format(9, 200), mode="a")
    collector.scan_once()
    assert env.backend.batches[-1]["payload"]["content"] == SYSLOG.format(9, 200)


def test_same_header_different_rows_is_not_mistaken_for_a_copy(env):
    header = "timestamp,source_ip,status\n"
    write(env.dir / "a.csv", header + "2026-10-25T10:00:00Z,10.0.0.1,failed\n")
    collector = env.make()
    collector.scan_once()
    write(env.dir / "b.csv", header + "2026-10-25T11:00:00Z,10.0.0.2,failed\n")
    collector.scan_once()
    assert len(env.backend.batches) == 2


def test_truncated_file_is_collected_again(env):
    log = env.dir / "auth.log"
    write(log, SYSLOG.format(1, 1) + SYSLOG.format(2, 2))
    collector = env.make()
    collector.scan_once()
    write(log, SYSLOG.format(3, 3))  # copytruncate then new line
    collector.scan_once()
    assert env.backend.batches[-1]["payload"]["content"] == SYSLOG.format(3, 3)


def test_whole_json_documents_dedupe_by_content(env):
    doc = json.dumps([{"timestamp": "2026-10-25T10:00:00Z", "event_type": "login", "status": "failed"}])
    write(env.dir / "export.json", doc)
    collector = env.make()
    collector.scan_once()
    write(env.dir / "export-again.json", doc)
    collector.scan_once()
    assert len(env.backend.batches) == 1


# ------------------------------------------------------------------ S7-02.4 retry


def test_unavailable_server_retries_same_chunk_with_backoff(env):
    write(env.dir / "auth.log", SYSLOG.format(1, 1))
    env.backend.fail_next = [503, "refused"]
    collector = env.make()
    collector.scan_once()
    assert env.backend.batches == [] and collector.retry_at > env.clock.now
    collector.scan_once()  # still backing off: no request
    assert env.backend.fail_next == ["refused"]
    env.clock.now = collector.retry_at
    collector.scan_once()
    env.clock.now = collector.retry_at
    collector.scan_once()
    assert len(env.backend.batches) == 1 and collector.failures == 0


def test_ambiguous_failure_that_was_stored_is_reconciled_not_resent(env):
    write(env.dir / "auth.log", SYSLOG.format(1, 1))
    env.backend.fail_next = ["timeout-after-store"]
    collector = env.make()
    collector.scan_once()
    collector.scan_once()
    assert len(env.backend.batches) == 1
    assert collector.stats["reconciled"] == 1
    assert collector.store.records and next(iter(collector.store.records.values())).pending_offset is None


def test_ambiguous_failure_that_was_not_stored_is_resent_after_backoff(env):
    write(env.dir / "auth.log", SYSLOG.format(1, 1))
    env.backend.fail_next = ["timeout-before-store"]
    collector = env.make()
    collector.scan_once()
    assert env.backend.batches == []
    assert collector.retry_at - env.clock.now >= 30
    record = next(iter(collector.store.records.values()))
    assert record.pending_offset == 0  # persisted: survives a restart
    env.clock.now = collector.retry_at
    collector.scan_once()
    assert len(env.backend.batches) == 1


def test_pending_reconciliation_survives_restart(env):
    write(env.dir / "auth.log", SYSLOG.format(1, 1))
    env.backend.fail_next = ["timeout-after-store", 503]  # history lookup sees the batch on restart
    collector = env.make()
    original_find = collector.client.find_unacknowledged_batch
    collector.client.find_unacknowledged_batch = lambda **kw: None  # first lookup misses (still committing)
    collector.scan_once()
    collector.client.find_unacknowledged_batch = original_find
    env.make().scan_once()  # restarted process
    assert len(env.backend.batches) == 1


def test_rejected_chunk_is_quarantined_and_collection_continues(env):
    log = env.dir / "auth.log"
    write(log, "garbage one\ngarbage two\n")
    collector = env.make()
    collector.scan_once()
    write(log, SYSLOG.format(1, 1), mode="a")
    collector.scan_once()
    assert env.backend.lines() == [SYSLOG.format(1, 1).strip()]
    rejected = list((env.tmp / "state" / "rejected").glob("*.chunk"))
    assert len(rejected) == 1 and "garbage one" in rejected[0].read_text()


# ------------------------------------------------------------------ authentication


def test_expired_access_token_is_refreshed_and_rotation_persisted(env):
    write(env.dir / "auth.log", SYSLOG.format(1, 1))
    collector = env.make()
    collector.scan_once()
    write(env.dir / "auth.log", SYSLOG.format(2, 2), mode="a")
    env.backend.expire_access = True
    collector.scan_once()
    assert len(env.backend.batches) == 2
    saved = json.loads((env.tmp / "state" / "session.json").read_text())
    assert saved["refresh_token"] == env.backend.refresh_token


def test_revoked_session_stops_collector_without_losing_data(env):
    write(env.dir / "auth.log", SYSLOG.format(1, 1))
    collector = env.make()
    env.backend.refresh_token = "revoked-elsewhere"
    with pytest.raises(CollectorStopped, match="login"):
        collector.scan_once()
    assert next(iter(collector.store.records.values())).offset == 0


def test_viewer_account_stops_collector(env):
    write(env.dir / "auth.log", SYSLOG.format(1, 1))
    env.backend.fail_next = [403]
    with pytest.raises(CollectorStopped, match="Admin or Analyst"):
        env.make().scan_once()


def test_login_saves_refresh_session_but_never_the_password(env):
    collector = env.make()
    (env.tmp / "state" / "session.json").unlink()
    user = collector.client.login("kapil", "s3cret-Passw0rd!", lambda email: "123456")
    saved = (env.tmp / "state" / "session.json").read_text()
    assert user["username"] == "kapil"
    assert "s3cret" not in saved and json.loads(saved)["refresh_token"] == env.backend.refresh_token
    if os.name == "posix":
        assert oct(os.stat(env.tmp / "state" / "session.json").st_mode & 0o777) == "0o600"


# ------------------------------------------------------------------ config


@pytest.mark.parametrize("change,message", [
    ({"api_url": "ftp://x"}, "api_url"),
    ({"sources": []}, "sources"),
    ({"sources": [{"name": "a", "path": "/x", "source_type": "bogus"}]}, "source_type"),
    ({"sources": [{"name": "a", "path": "/x"}, {"name": "a", "path": "/y"}]}, "used twice"),
    ({"max_chunk_bytes": 10}, "max_chunk_bytes"),
])
def test_invalid_config_is_rejected(change, message, monkeypatch):
    monkeypatch.delenv("CYBERSHIELD_API_URL", raising=False)
    raw = {"api_url": API, "sources": [{"name": "a", "path": "/x"}], **change}
    with pytest.raises(ConfigError, match=message):
        parse_config(raw)


def test_state_file_round_trip(tmp_path):
    store = StateStore(tmp_path)
    store.remember_upload("u1")
    store.save()
    assert list(StateStore(tmp_path).known_uploads) == ["u1"]
