"""Unit coverage for custom_rule_repository's rule_id race-condition retry.

next_rule_id() reads the highest existing id without locking, so two
concurrent creates can compute the same "R-###" and collide on the unique
index. create_custom_rule() must retry with a fresh id instead of bubbling
the IntegrityError up as a 500.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from sqlalchemy.exc import IntegrityError

from app.repositories.custom_rule_repository import create_custom_rule

pytestmark = pytest.mark.no_db


def _base_kwargs():
    return dict(
        name="Off-hours privilege escalation",
        category="generic_detection",
        severity="HIGH",
        tactic=None,
        conditions=[{"field": "event_type", "operator": "equals", "value": "privilege_escalation"}],
        group_by="none",
        window_seconds=600,
        actions={},
        status="DRAFT",
        dsl=None,
        created_by=1,
    )


def _db_with_no_existing_rules():
    db = MagicMock()
    db.execute.return_value = []  # next_rule_id()'s scan finds no stored rows
    db.begin_nested.return_value.__exit__.return_value = False  # don't swallow exceptions
    return db


def test_create_custom_rule_retries_once_on_rule_id_collision():
    db = _db_with_no_existing_rules()
    db.flush.side_effect = [IntegrityError("INSERT", {}, Exception("duplicate key")), None]

    rule = create_custom_rule(db, **_base_kwargs())

    assert db.flush.call_count == 2
    # A real savepoint rollback expunges the failed pending instance itself.
    assert db.expunge.call_count == 0
    assert db.add.call_count == 2
    assert rule is not None


def test_create_custom_rule_raises_after_exhausting_retries():
    db = _db_with_no_existing_rules()
    db.flush.side_effect = IntegrityError("INSERT", {}, Exception("duplicate key"))

    with pytest.raises(IntegrityError):
        create_custom_rule(db, **_base_kwargs())

    assert db.flush.call_count == 5


def test_create_custom_rule_succeeds_without_collision():
    db = _db_with_no_existing_rules()

    rule = create_custom_rule(db, **_base_kwargs())

    assert db.flush.call_count == 1
    assert db.expunge.call_count == 0
    assert rule.rule_id == "R-109"


def test_insert_is_added_inside_savepoint_not_before_it():
    db = _db_with_no_existing_rules()
    create_custom_rule(db, **_base_kwargs())
    calls = [str(call) for call in db.mock_calls]
    entered = next(i for i, call in enumerate(calls) if call.startswith("call.begin_nested().__enter__"))
    added = next(i for i, call in enumerate(calls) if call.startswith("call.add("))
    assert entered < added


def test_partial_actions_merge_and_nullable_fields_can_be_cleared():
    from app.models.custom_rule import CustomRule
    from app.repositories.custom_rule_repository import update_custom_rule

    db = MagicMock()
    rule = CustomRule(actions={"create_alert": True, "notify_slack": True}, tactic="TA0001", dsl="old")
    db.get.return_value = rule
    update_custom_rule(db, rule_pk=1, updates={"actions": {"notify_slack": False}, "tactic": None, "dsl": None})
    assert rule.actions == {"create_alert": True, "notify_slack": False}
    assert rule.tactic is None and rule.dsl is None


@pytest.mark.db
def test_real_unique_collision_preserves_outer_transaction(db_session, monkeypatch):
    from app.repositories import custom_rule_repository as repository

    kwargs = {**_base_kwargs(), "created_by": None}
    first = create_custom_rule(db_session, **kwargs)
    original = repository.next_rule_id
    calls = 0

    def colliding_id(db):
        nonlocal calls
        calls += 1
        return first.rule_id if calls == 1 else original(db)

    monkeypatch.setattr(repository, "next_rule_id", colliding_id)
    second = create_custom_rule(db_session, **kwargs)
    assert second.rule_id != first.rule_id
    assert db_session.get(type(first), first.id) is first
    assert db_session.is_active
