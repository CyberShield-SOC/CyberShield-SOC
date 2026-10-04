"""Read-only data tools the AI assistant can call.

Every tool here only runs SELECT queries. There is deliberately no tool that
blocks an IP, locks an account, changes an alert/incident, or edits a setting:
the assistant can only be as powerful as this module, so keeping it read-only
is what enforces "advise, never act" regardless of what the model is told.

Tool results are bounded (row limits, truncated text) so one question cannot
pull the whole workspace into the model's context.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from typing import Any, Callable

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.assistant.safety import mark_suspected_injection
from app.core.config import settings
from app.detection.engine import _RULE_CLASSES
from app.models.alert import Alert
from app.models.incident import Incident
from app.models.log import Log
from app.models.user import User
from app.repositories.detection_rule_setting_repository import effective_rule_configs

MAX_HOURS = 24 * 90
DEFAULT_LIMIT = 20
MAX_LIMIT = 50
TOP_N = 10
RAW_MESSAGE_CHARS = 200
DESCRIPTION_CHARS = 300


class ToolInputError(ValueError):
    """The model passed arguments a tool cannot use; the message is shown to it."""


@dataclass(frozen=True)
class ToolContext:
    db: Session
    user: User
    default_hours: int
    now: datetime


# ---------------------------------------------------------------- helpers


def _hours(args: dict[str, Any], ctx: ToolContext) -> int:
    value = args.get("hours", ctx.default_hours)
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= MAX_HOURS:
        raise ToolInputError(f"hours must be an integer between 1 and {MAX_HOURS}.")
    return value


def _limit(args: dict[str, Any]) -> int:
    value = args.get("limit", DEFAULT_LIMIT)
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= MAX_LIMIT:
        raise ToolInputError(f"limit must be an integer between 1 and {MAX_LIMIT}.")
    return value


def _id(args: dict[str, Any], key: str) -> int | None:
    value = args.get(key)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 2**63 - 1:
        raise ToolInputError(f"{key} must be a positive integer.")
    return value


def _upper_choice(args: dict[str, Any], key: str, allowed: set[str]) -> str | None:
    value = args.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or value.upper() not in allowed:
        raise ToolInputError(f"{key} must be one of: {', '.join(sorted(allowed))}.")
    return value.upper()


def _ip(args: dict[str, Any], key: str) -> str | None:
    value = args.get(key)
    if value is None:
        return None
    try:
        return str(ip_address(str(value).strip()))
    except ValueError as exc:
        raise ToolInputError(f"{key} is not a valid IP address.") from exc


def _text(args: dict[str, Any], key: str, max_len: int = 100) -> str | None:
    value = args.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip() or len(value) > max_len:
        raise ToolInputError(f"{key} must be a non-empty string up to {max_len} characters.")
    return value.strip()


def _clip(value: str | None, limit: int) -> str | None:
    if value is None or len(value) <= limit:
        return value
    return value[: limit - 1] + "…"


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _window(ctx: ToolContext, hours: int) -> datetime:
    return ctx.now - timedelta(hours=hours)


def _page(rows: list[Any], limit: int) -> tuple[list[Any], bool]:
    """Queries fetch limit+1 rows so truncation is detectable without COUNT(*)."""

    return rows[:limit], len(rows) > limit


def _event_time():
    return func.coalesce(Log.event_timestamp, Log.ingested_at)


# ------------------------------------------------------------------ tools


def list_alerts(args: dict[str, Any], ctx: ToolContext) -> dict[str, Any]:
    hours, limit = _hours(args, ctx), _limit(args)
    severity = _upper_choice(args, "severity", {"LOW", "MEDIUM", "HIGH", "CRITICAL"})
    status = _upper_choice(args, "status", {"NEW", "REVIEWING", "ESCALATED", "CLOSED"})
    source_ip = _ip(args, "source_ip")
    username = _text(args, "username")
    rule = _text(args, "rule")
    alert_id = _id(args, "alert_id")

    statement = select(Alert)
    if alert_id is not None:
        # A lookup by ID is exact: the analyst's time range must not hide it.
        statement = statement.where(Alert.id == alert_id)
    else:
        statement = statement.where(Alert.created_at >= _window(ctx, hours))
    if severity:
        statement = statement.where(Alert.severity == severity)
    if status:
        statement = statement.where(Alert.status == status)
    if source_ip:
        statement = statement.where(Alert.source_ip == source_ip)
    if username:
        statement = statement.where(func.lower(Alert.username) == username.lower())
    if rule:
        statement = statement.where(Alert.rule == rule)
    statement = statement.order_by(Alert.created_at.desc(), Alert.id.desc()).limit(limit + 1)

    rows, truncated = _page(list(ctx.db.scalars(statement).all()), limit)
    result = {
        "time_window_hours": hours,
        "count": len(rows),
        "truncated": truncated,
        "order": "newest_first",
        "alerts": [
            {
                "id": a.id,
                "rule": a.rule,
                "title": a.title,
                "severity": a.severity,
                "status": a.status,
                "source_ip": str(a.source_ip) if a.source_ip is not None else None,
                "username": a.username,
                "hostname": a.hostname,
                "event_count": a.event_count,
                "confidence": a.confidence,
                "mitre_technique": a.mitre_technique,
                "first_seen": _iso(a.first_seen),
                "last_seen": _iso(a.last_seen),
                "created_at": _iso(a.created_at),
                "description": _clip(a.description, DESCRIPTION_CHARS),
            }
            for a in rows
        ],
    }
    return mark_suspected_injection(result, "alerts", [(a.title, a.description, a.username, a.hostname) for a in rows])


def list_incidents(args: dict[str, Any], ctx: ToolContext) -> dict[str, Any]:
    hours, limit = _hours(args, ctx), _limit(args)
    status = _upper_choice(args, "status", {"OPEN", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"})
    priority = _upper_choice(args, "priority", {"LOW", "MEDIUM", "HIGH", "CRITICAL"})
    incident_id = _id(args, "incident_id")

    statement = select(Incident)
    if incident_id is not None:
        statement = statement.where(Incident.id == incident_id)
    else:
        statement = statement.where(Incident.created_at >= _window(ctx, hours))
    if status:
        statement = statement.where(Incident.status == status)
    if priority:
        statement = statement.where(Incident.priority == priority)
    statement = statement.order_by(Incident.created_at.desc(), Incident.id.desc()).limit(limit + 1)

    rows, truncated = _page(list(ctx.db.scalars(statement).all()), limit)
    result = {
        "time_window_hours": hours,
        "count": len(rows),
        "truncated": truncated,
        "order": "newest_first",
        "incidents": [
            {
                "id": i.id,
                "source_alert_id": i.source_alert_id,
                "title": i.title,
                "priority": i.priority,
                "status": i.status,
                "assigned_user_id": i.assigned_user_id,
                "opened_at": _iso(i.opened_at),
                "resolved_at": _iso(i.resolved_at),
                "description": _clip(i.description, DESCRIPTION_CHARS),
            }
            for i in rows
        ],
    }
    return mark_suspected_injection(result, "incidents", [(i.title, i.description) for i in rows])


def search_events(args: dict[str, Any], ctx: ToolContext) -> dict[str, Any]:
    hours, limit = _hours(args, ctx), _limit(args)
    event_type = _text(args, "event_type")
    status = _text(args, "status", 30)
    source_ip = _ip(args, "source_ip")
    username = _text(args, "username")
    severity = _text(args, "severity", 30)
    event_id = _id(args, "event_id")

    ts = _event_time()
    statement = select(Log)
    if event_id is not None:
        statement = statement.where(Log.id == event_id)
    else:
        statement = statement.where(ts >= _window(ctx, hours))
    if event_type:
        statement = statement.where(Log.event_type == event_type)
    if status:
        statement = statement.where(Log.status == status.upper())
    if source_ip:
        statement = statement.where(Log.ip_address == source_ip)
    if username:
        statement = statement.where(func.lower(Log.username) == username.lower())
    if severity:
        statement = statement.where(func.upper(Log.severity) == severity.upper())
    statement = statement.order_by(ts.desc(), Log.id.desc()).limit(limit + 1)

    rows, truncated = _page(list(ctx.db.scalars(statement).all()), limit)
    # The query picks the newest `limit` events; present them in the order they
    # happened so sequence ("X before Y") can be read straight off the list.
    rows = rows[::-1]
    result = {
        "time_window_hours": hours,
        "count": len(rows),
        "truncated": truncated,
        "order": "oldest_first",
        "events": [
            {
                "id": e.id,
                "timestamp": _iso(e.event_timestamp or e.ingested_at),
                "event_type": e.event_type,
                "status": e.status,
                "severity": e.severity,
                "source_ip": str(e.ip_address) if e.ip_address is not None else None,
                "username": e.username,
                "port": e.port,
                "source_filename": e.source_filename,
                "message": _clip(e.raw_message, RAW_MESSAGE_CHARS),
            }
            for e in rows
        ],
    }
    return mark_suspected_injection(result, "events", [(e.raw_message, e.username) for e in rows])


def auth_activity(args: dict[str, Any], ctx: ToolContext) -> dict[str, Any]:
    """Aggregate login_attempt events: totals plus the top offending IPs/users."""

    hours = _hours(args, ctx)
    source_ip = _ip(args, "source_ip")
    username = _text(args, "username")

    ts = _event_time()
    conditions = [Log.event_type == "login_attempt", ts >= _window(ctx, hours)]
    if source_ip:
        conditions.append(Log.ip_address == source_ip)
    if username:
        conditions.append(func.lower(Log.username) == username.lower())

    failed = Log.status == "FAILED"
    total, failed_count, success_count = ctx.db.execute(
        select(
            func.count(),
            func.count().filter(failed),
            func.count().filter(Log.status == "SUCCESS"),
        ).where(*conditions)
    ).one()

    def top(column, outcome) -> list[dict[str, Any]]:
        statement = (
            select(column, func.count().label("n"))
            .where(*conditions, column.is_not(None), outcome)
            .group_by(column)
            .order_by(func.count().desc())
            .limit(TOP_N)
        )
        return [{"value": str(value), "count": n} for value, n in ctx.db.execute(statement).all()]

    # Totals say nothing about order. These timestamps and before/after counts
    # let "N failures, then a success" be stated from data, not inferred.
    success = Log.status == "SUCCESS"
    first_failed, last_failed, first_success, last_success = ctx.db.execute(
        select(
            func.min(ts).filter(failed),
            func.max(ts).filter(failed),
            func.min(ts).filter(success),
            func.max(ts).filter(success),
        ).where(*conditions)
    ).one()
    failed_before = failed_after = None
    if first_success is not None:
        failed_before = ctx.db.scalar(select(func.count()).where(*conditions, failed, ts < first_success))
        failed_after = ctx.db.scalar(select(func.count()).where(*conditions, failed, ts > first_success))

    return {
        "time_window_hours": hours,
        "total_login_attempts": total,
        "failed": failed_count,
        "successful": success_count,
        "other_or_unknown_status": total - failed_count - success_count,
        "sequence": {
            "note": "Computed over the attempts matching the filters used (source_ip/username if given).",
            "first_failed_at": _iso(first_failed),
            "last_failed_at": _iso(last_failed),
            "first_success_at": _iso(first_success),
            "last_success_at": _iso(last_success),
            "failures_before_first_success": failed_before,
            "failures_after_first_success": failed_after,
        },
        "top_source_ips_by_failures": top(Log.ip_address, failed),
        "top_usernames_by_failures": top(Log.username, failed),
        "top_source_ips_by_successes": top(Log.ip_address, Log.status == "SUCCESS"),
    }


def list_users(args: dict[str, Any], ctx: ToolContext) -> dict[str, Any]:
    limit = _limit(args)
    rows, truncated = _page(
        list(ctx.db.scalars(select(User).order_by(User.username).limit(limit + 1)).all()),
        limit,
    )
    # Deliberately no email/password data: the assistant only needs to know who
    # exists and what they can do.
    return {
        "count": len(rows),
        "truncated": truncated,
        "users": [
            {
                "id": u.id,
                "username": u.username,
                "full_name": u.full_name,
                "role": u.role.name if u.role else None,
                "is_active": u.is_active,
            }
            for u in rows
        ],
    }


def list_detection_rules(args: dict[str, Any], ctx: ToolContext) -> dict[str, Any]:
    configs = effective_rule_configs(ctx.db, settings.detection_rule_config)
    rules = []
    for rule_cls in _RULE_CLASSES:
        rule = rule_cls()
        rules.append(
            {
                "name": rule.name,
                "description": rule.description,
                "severity": rule.severity,
                "mitre_technique": rule.mitre_technique or None,
                "entity_type": rule.entity_type,
                "config": configs[rule.name].model_dump(),
            }
        )
    return {"count": len(rules), "rules": rules}


# ------------------------------------------------------------- registry

_WINDOW_PROP = {
    "type": "integer",
    "minimum": 1,
    "maximum": MAX_HOURS,
    "description": "Look-back window in hours. Omit to use the analyst's current time range.",
}
_LIMIT_PROP = {
    "type": "integer",
    "minimum": 1,
    "maximum": MAX_LIMIT,
    "description": f"Max rows to return (default {DEFAULT_LIMIT}).",
}


def _ID_PROP(kind: str) -> dict[str, Any]:
    return {
        "type": "integer",
        "minimum": 1,
        "description": f"Look up one {kind} by its numeric ID. Ignores the time window.",
    }


def _schema(properties: dict[str, Any]) -> dict[str, Any]:
    return {"type": "object", "properties": properties, "additionalProperties": False}


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    input_schema: dict[str, Any]
    run: Callable[[dict[str, Any], ToolContext], dict[str, Any]]
    roles: frozenset[str] = frozenset({"admin", "analyst", "viewer"})

    def definition(self) -> dict[str, Any]:
        return {"name": self.name, "description": self.description, "input_schema": self.input_schema}


TOOLS: tuple[Tool, ...] = (
    Tool(
        "list_alerts",
        "List detection alerts (newest first) created in the time window, optionally filtered. "
        "Use for questions about what fired, how severe it is, or alerts for one IP, user or rule.",
        _schema(
            {
                "hours": _WINDOW_PROP,
                "severity": {"type": "string", "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]},
                "status": {"type": "string", "enum": ["NEW", "REVIEWING", "ESCALATED", "CLOSED"]},
                "source_ip": {"type": "string", "description": "Exact IPv4/IPv6 address."},
                "username": {"type": "string"},
                "rule": {"type": "string", "description": "Exact detection rule name."},
                "alert_id": _ID_PROP("alert"),
                "limit": _LIMIT_PROP,
            }
        ),
        list_alerts,
    ),
    Tool(
        "list_incidents",
        "List incidents (newest first) opened in the time window, optionally by status or priority.",
        _schema(
            {
                "hours": _WINDOW_PROP,
                "status": {"type": "string", "enum": ["OPEN", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"]},
                "priority": {"type": "string", "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]},
                "incident_id": _ID_PROP("incident"),
                "limit": _LIMIT_PROP,
            }
        ),
        list_incidents,
    ),
    Tool(
        "search_events",
        "Search individual parsed log events (newest first). Use to inspect specific activity for an IP, "
        "user, event type or status. For login/auth totals prefer auth_activity.",
        _schema(
            {
                "hours": _WINDOW_PROP,
                "event_type": {"type": "string", "description": "e.g. login_attempt."},
                "status": {"type": "string", "description": "e.g. FAILED, SUCCESS."},
                "severity": {"type": "string"},
                "source_ip": {"type": "string", "description": "Exact IPv4/IPv6 address."},
                "username": {"type": "string"},
                "event_id": _ID_PROP("event"),
                "limit": _LIMIT_PROP,
            }
        ),
        search_events,
    ),
    Tool(
        "auth_activity",
        "Summarise login attempts in the time window: total, failed and successful counts, plus the top "
        "source IPs and usernames by failures. Optionally scope to one IP or username. Use for brute "
        "force, password spraying and failed-login questions.",
        _schema(
            {
                "hours": _WINDOW_PROP,
                "source_ip": {"type": "string", "description": "Exact IPv4/IPv6 address."},
                "username": {"type": "string"},
            }
        ),
        auth_activity,
    ),
    Tool(
        "list_users",
        "List platform user accounts with role and active status (no contact or credential data).",
        _schema({"limit": _LIMIT_PROP}),
        list_users,
        roles=frozenset({"admin"}),
    ),
    Tool(
        "list_detection_rules",
        "List the built-in detection rules with severity, MITRE technique and current thresholds/enabled state.",
        _schema({}),
        list_detection_rules,
    ),
)

_BY_NAME = {tool.name: tool for tool in TOOLS}


def _role(user: User) -> str:
    return (user.role.name if user.role else "").lower()


def tools_for(user: User) -> list[Tool]:
    """Only the tools this user's role may read — mirrors the REST API's RBAC."""

    role = _role(user)
    return [tool for tool in TOOLS if role in tool.roles]


def run_tool(name: str, args: Any, ctx: ToolContext) -> dict[str, Any]:
    """Execute one tool. Raises ToolInputError for unknown/forbidden tools or bad args."""

    tool = _BY_NAME.get(name)
    if tool is None or _role(ctx.user) not in tool.roles:
        raise ToolInputError(f"Tool '{name}' is not available.")
    if not isinstance(args, dict):
        raise ToolInputError("Tool arguments must be a JSON object.")
    unknown = set(args) - set(tool.input_schema["properties"])
    if unknown:
        raise ToolInputError(f"Unknown argument(s): {', '.join(sorted(unknown))}.")
    return tool.run(args, ctx)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)
