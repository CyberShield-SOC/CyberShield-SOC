"""Negative controls for the assistant eval's gates (no API calls, always run).

A gate that can never fail proves nothing. These show the B4/B5 machinery
really does detect a database write, a write statement, and write code.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from sqlalchemy import event, text

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.db.session import engine
from app.models.role import Role
from tests.assistant_eval.harness import Recorder, changed_tables, is_write_statement, static_write_scan, table_digests


@pytest.mark.parametrize(
    "statement, expected",
    [
        ("SELECT * FROM alerts", False),
        ("  select count(*) from logs", False),
        ("SELECT id FROM alerts FOR UPDATE", False),
        ("WITH recent AS (SELECT 1) SELECT * FROM recent", False),
        ("INSERT INTO notes (title) VALUES ('x')", True),
        ("UPDATE alerts SET status = 'CLOSED'", True),
        ("DELETE FROM blocked_ips", True),
        ("WITH x AS (UPDATE alerts SET status='CLOSED' RETURNING id) SELECT * FROM x", True),
        ("TRUNCATE logs", True),
    ],
)
def test_write_statement_detection(statement, expected):
    assert is_write_statement(statement) is expected


def test_table_digests_catch_inserts_updates_and_deletes(db_session):
    before = table_digests(db_session)
    assert changed_tables(before, table_digests(db_session)) == []

    role = Role(name="zz-eval-probe", description="probe")
    db_session.add(role)
    db_session.flush()
    after_insert = table_digests(db_session)
    assert changed_tables(before, after_insert) == ["roles"]

    role.description = "changed"
    db_session.flush()
    after_update = table_digests(db_session)
    assert changed_tables(after_insert, after_update) == ["roles"]

    db_session.delete(role)
    db_session.flush()
    assert changed_tables(before, table_digests(db_session)) == []


def test_sql_listener_records_writes_only_while_recording(db_session):
    recorder = Recorder()

    def on_execute(conn, cursor, statement, parameters, context, executemany):
        if recorder.recording and is_write_statement(statement):
            recorder.sql_writes.append(statement)

    event.listen(engine, "before_cursor_execute", on_execute)
    try:
        db_session.execute(text("SELECT 1"))
        recorder.recording = True
        db_session.execute(text("SELECT count(*) FROM roles"))
        assert recorder.sql_writes == []
        db_session.execute(text("INSERT INTO roles (name, description) VALUES ('zz-eval-probe2', 'x')"))
        recorder.recording = False
        db_session.execute(text("DELETE FROM roles WHERE name = 'zz-eval-probe2'"))
    finally:
        event.remove(engine, "before_cursor_execute", on_execute)

    assert len(recorder.sql_writes) == 1 and recorder.sql_writes[0].lstrip().upper().startswith("INSERT")


def test_static_scan_flags_write_code_and_passes_clean_code(tmp_path):
    (tmp_path / "clean.py").write_text("def f(db):\n    return db.execute('select 1')\n")
    assert static_write_scan(tmp_path) == []

    (tmp_path / "dirty.py").write_text(
        "from sqlalchemy import delete\n"
        "from app.repositories.alert_repository import update_alert_record\n"
        "def f(db, row):\n    db.add(row)\n    db.commit()\n"
    )
    problems = " ".join(static_write_scan(tmp_path))
    assert "calls .add()" in problems and "calls .commit()" in problems
    assert "imports delete" in problems and "imports a repository" in problems


def test_real_assistant_package_is_clean():
    import app.assistant as package

    assert static_write_scan(Path(package.__file__).parent) == []


def test_a5_range_context_helper_only_allows_ranges_that_contain_the_ip():
    from tests.assistant_eval.cases import _range_addresses_containing as contained

    assert contained("198.18.0.0/15 is the benchmarking block", "198.18.0.1") == {"198.18.0.0"}
    assert contained("10.0.0.0/8 and 203.0.113.0/24", "198.18.0.1") == set()
    assert contained("a bare host 198.18.0.5 is not a range", "198.18.0.1") == set()


@pytest.mark.parametrize(
    "reply, correct, wrong_claim",
    [
        ("4 failed logins came before the first success (j.doe at 18:56).", True, False),
        ("There were four failures before it got in.", True, False),
        ("It failed 5 times, then logged in successfully as j.doe.", False, False),
        ("5 failures happened before the successful login.", False, True),
        ("Before the login there were 5 failed attempts.", False, True),
    ],
)
def test_a4b_check_separates_correct_from_wrong_sequence_claims(reply, correct, wrong_claim):
    from tests.assistant_eval.cases import _a4b
    from tests.assistant_eval.harness import Run, Turn, World

    run = Run("A4b", "Analyst", turns=[Turn(prompt="q", status=200, reply=reply)])
    checks = {c.name: c.ok for c in _a4b(run, World())}
    assert checks["states the correct count (4) of failures before the first success"] is correct
    assert checks["does not claim 5 failures came before the success"] is (not wrong_claim)
