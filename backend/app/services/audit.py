"""Write and read the platform audit trail (see app/models/audit_event.py).

Callers add the event to their own transaction and commit it together with
the change it describes, so a change and its record land or fail as one.
Never put a secret in ``detail``: no passwords, codes, tokens, or reset links.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime

from fastapi import Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.rate_limit import client_ip
from app.models.audit_event import AuditEvent
from app.models.user import User


ANONYMOUS_ACTOR = "Anonymous"

# The first segment of an action name, e.g. "auth" in "auth.login.password".
AUDIT_CATEGORIES = (
    "auth",
    "user",
    "rule",
    "threat_intel",
    "ml",
    "log",
    "export",
)


@dataclass(frozen=True)
class AuditOrigin:
    """Where a request came from, captured for code that runs off the request."""

    ip_address: str | None
    user_agent: str | None


def origin_of(request: Request | None) -> AuditOrigin:
    if request is None:
        return AuditOrigin(None, None)
    try:
        ip = str(ipaddress.ip_address(client_ip(request)))
    except ValueError:
        ip = None  # e.g. Starlette's TestClient reports "testclient"
    agent = request.headers.get("user-agent")
    return AuditOrigin(ip, agent[:300] if agent else None)


def record_audit(
    db: Session,
    origin: Request | AuditOrigin | None,
    *,
    action: str,
    actor: User | None = None,
    outcome: str = "SUCCESS",
    target_type: str | None = None,
    target_id: object | None = None,
    target_label: str | None = None,
    detail: dict | None = None,
) -> AuditEvent:
    """Add one audit event to the session and flush it. The caller commits."""

    if not isinstance(origin, AuditOrigin):
        origin = origin_of(origin)
    role = actor.role.name if actor is not None and actor.role else None
    event = AuditEvent(
        actor_user_id=actor.id if actor is not None else None,
        actor_name=(
            (actor.full_name or actor.username)[:100]
            if actor is not None
            else ANONYMOUS_ACTOR
        ),
        actor_role=role,
        action=action,
        outcome=outcome,
        target_type=target_type,
        target_id=str(target_id)[:100] if target_id is not None else None,
        target_label=target_label[:255] if target_label else None,
        ip_address=origin.ip_address,
        user_agent=origin.user_agent,
        detail=detail or {},
    )
    db.add(event)
    db.flush()
    return event


def user_target(user: User) -> dict:
    """Keyword arguments naming an account as the thing acted on."""

    return {
        "target_type": "user",
        "target_id": user.id,
        "target_label": user.username,
    }


def serialize_audit_event(event: AuditEvent) -> dict:
    return {
        "id": event.id,
        "occurred_at": event.occurred_at.isoformat(),
        "actor_user_id": event.actor_user_id,
        "actor_name": event.actor_name,
        "actor_role": event.actor_role,
        "action": event.action,
        "outcome": event.outcome,
        "target_type": event.target_type,
        "target_id": event.target_id,
        "target_label": event.target_label,
        "ip_address": str(event.ip_address) if event.ip_address is not None else None,
        "user_agent": event.user_agent,
        "detail": event.detail,
    }


def audit_page(
    db: Session,
    *,
    category: str | None = None,
    actor: str | None = None,
    outcome: str | None = None,
    occurred_from: datetime | None = None,
    occurred_to: datetime | None = None,
    before_id: int | None = None,
    limit: int = 50,
) -> dict:
    """Newest-first page of audit events with an exclusive ``before_id`` cursor."""

    query = select(AuditEvent)
    if category:
        query = query.where(AuditEvent.action.like(f"{category}.%"))
    if actor:
        pattern = f"%{actor.strip().replace('%', r'\%').replace('_', r'\_')}%"
        query = query.where(AuditEvent.actor_name.ilike(pattern, escape="\\"))
    if outcome:
        query = query.where(AuditEvent.outcome == outcome)
    if occurred_from is not None:
        query = query.where(AuditEvent.occurred_at >= occurred_from)
    if occurred_to is not None:
        query = query.where(AuditEvent.occurred_at <= occurred_to)
    if before_id is not None:
        query = query.where(AuditEvent.id < before_id)

    rows = list(db.scalars(query.order_by(AuditEvent.id.desc()).limit(limit + 1)))
    visible = rows[:limit]
    return {
        "success": True,
        "events": [serialize_audit_event(event) for event in visible],
        "next_before_id": visible[-1].id if len(rows) > limit else None,
    }
