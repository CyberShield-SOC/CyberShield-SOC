from __future__ import annotations

import re

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.custom_rule import CustomRule

MAX_RULE_ID_ATTEMPTS = 5

BUILTIN_RULE_COUNT = 8  # R-101..R-108 ship with the DetectionEngine
_RULE_NUMBER_RE = re.compile(r"^R-(\d+)$")


class CustomRuleNotFoundError(Exception):
    """Raised when the requested custom rule does not exist."""


def next_rule_id(db: Session) -> str:
    """Return the next free R-### identifier after the built-in and stored rules."""

    highest = BUILTIN_RULE_COUNT + 100  # R-108 -> 108
    for (rule_id,) in db.execute(select(CustomRule.rule_id)):
        match = _RULE_NUMBER_RE.match(rule_id)
        if match:
            highest = max(highest, int(match.group(1)))
    return f"R-{highest + 1}"


def create_custom_rule(
    db: Session,
    *,
    name: str,
    category: str,
    severity: str,
    tactic: str | None,
    conditions: list[dict],
    group_by: str,
    window_seconds: int,
    actions: dict[str, bool],
    status: str,
    dsl: str | None,
    created_by: int | None,
) -> CustomRule:
    """
    Persist a new custom rule with an auto-assigned rule_id.

    next_rule_id() reads the highest existing id without locking, so two
    concurrent creates can compute the same id. Retry inside a savepoint on
    the resulting unique-constraint violation rather than surfacing a 500
    to one of the two callers.
    """

    for attempt in range(MAX_RULE_ID_ATTEMPTS):
        rule = CustomRule(
            rule_id=next_rule_id(db),
            name=name,
            category=category,
            severity=severity,
            tactic=tactic,
            conditions=conditions,
            group_by=None if group_by == "none" else group_by,
            window_seconds=window_seconds,
            actions=actions,
            status=status,
            dsl=dsl,
            created_by=created_by,
        )
        db.add(rule)
        try:
            with db.begin_nested():
                db.flush()
            return rule
        except IntegrityError:
            db.expunge(rule)
            if attempt == MAX_RULE_ID_ATTEMPTS - 1:
                raise

    raise AssertionError("unreachable")  # pragma: no cover


def list_custom_rules(db: Session, *, limit: int = 200) -> list[CustomRule]:
    """Return custom rules, newest first."""

    statement = (
        select(CustomRule)
        .order_by(CustomRule.created_at.desc(), CustomRule.id.desc())
        .limit(limit)
    )
    return list(db.scalars(statement).all())


def list_enabled_custom_rules(db: Session) -> list[CustomRule]:
    """Return rules the detection engine should evaluate on new uploads."""

    statement = select(CustomRule).where(CustomRule.status == "ENABLED")
    return list(db.scalars(statement).all())


def get_custom_rule(db: Session, *, rule_pk: int) -> CustomRule:
    rule = db.get(CustomRule, rule_pk)
    if rule is None:
        raise CustomRuleNotFoundError(f"Custom rule {rule_pk} does not exist.")
    return rule


def update_custom_rule(db: Session, *, rule_pk: int, updates: dict) -> CustomRule:
    """Update the editable fields of a custom rule."""

    rule = get_custom_rule(db, rule_pk=rule_pk)

    for field in (
        "name",
        "category",
        "severity",
        "tactic",
        "window_seconds",
        "actions",
        "status",
        "dsl",
    ):
        if field in updates and updates[field] is not None:
            setattr(rule, field, updates[field])

    if "conditions" in updates and updates["conditions"] is not None:
        rule.conditions = updates["conditions"]

    if "group_by" in updates and updates["group_by"] is not None:
        rule.group_by = None if updates["group_by"] == "none" else updates["group_by"]

    db.flush()
    return rule


def delete_custom_rule(db: Session, *, rule_pk: int) -> None:
    rule = get_custom_rule(db, rule_pk=rule_pk)
    db.delete(rule)
    db.flush()


def serialize_custom_rule(rule: CustomRule) -> dict:
    """Convert a stored custom rule into the current API response shape."""

    return {
        "id": rule.id,
        "rule_id": rule.rule_id,
        "name": rule.name,
        "category": rule.category,
        "severity": rule.severity,
        "tactic": rule.tactic,
        "conditions": rule.conditions,
        "group_by": rule.group_by or "none",
        "window_seconds": rule.window_seconds,
        "actions": rule.actions,
        "status": rule.status,
        "dsl": rule.dsl,
        "executable": True,
        "created_by": rule.created_by,
        "created_at": rule.created_at.isoformat(),
        "updated_at": rule.updated_at.isoformat(),
    }
