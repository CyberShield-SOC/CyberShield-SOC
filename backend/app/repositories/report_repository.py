"""Read-only aggregate queries for the PDF report builders.

Every function aggregates in SQL — nothing here loads a full result set into
Python just to count or sum it. Listing functions that back a table in the
PDF return `(rows, total_count)` so the builder can print "Showing N of M"
when a table is capped at `settings.report_max_rows_per_table`.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from sqlalchemy import case, func, select
from sqlalchemy.orm import Session, aliased

from app.core.config import settings
from app.models.alert import Alert
from app.models.host_heartbeat import HostHeartbeat
from app.models.incident import Incident
from app.models.user import User
from app.repositories.detection_rule_setting_repository import (
    effective_rule_configs,
)
from app.detection.engine import _RULE_CLASSES

BucketUnit = Literal["hour", "day"]


def _bucket(column, tz_name: str, unit: BucketUnit):
    return func.date_trunc(unit, func.timezone(tz_name, column))


def _resolve_seconds(opened, resolved):
    return func.extract("epoch", resolved - opened)


def _rows(db: Session, statement) -> list[dict[str, Any]]:
    return [dict(row._mapping) for row in db.execute(statement).all()]


def _count_and_limited(db: Session, count_stmt, rows_stmt, limit: int) -> tuple[list[dict[str, Any]], int]:
    total = db.scalar(count_stmt) or 0
    rows = _rows(db, rows_stmt.limit(limit))
    return rows, total


def cap_rows(rows: list, limit: int) -> tuple[list, int]:
    """Cap an already-small, fully-materialized row list for table display."""

    return rows[:limit], len(rows)


def _assignee_label(user_full_name, user_username):
    return case(
        (user_full_name.is_not(None), user_full_name),
        else_=user_username,
    )


# --------------------------------------------------------------------------
# Alert-based aggregates (Daily SOC operations, Detection coverage, Executive)
# --------------------------------------------------------------------------


def alerts_over_time_by_severity(
    db: Session, *, start: datetime, end: datetime, tz_name: str, unit: BucketUnit, severity: str | None = None,
) -> list[dict[str, Any]]:
    bucket = _bucket(Alert.created_at, tz_name, unit).label("bucket")
    statement = (
        select(bucket, Alert.severity, func.count().label("count"))
        .where(Alert.created_at >= start, Alert.created_at < end)
    )
    if severity:
        statement = statement.where(Alert.severity == severity)
    statement = statement.group_by(bucket, Alert.severity).order_by(bucket)
    return _rows(db, statement)


def alerts_by_status(db: Session, *, start: datetime, end: datetime, severity: str | None = None) -> list[dict[str, Any]]:
    statement = (
        select(Alert.status, func.count().label("count"))
        .where(Alert.created_at >= start, Alert.created_at < end)
    )
    if severity:
        statement = statement.where(Alert.severity == severity)
    statement = statement.group_by(Alert.status).order_by(func.count().desc())
    return _rows(db, statement)


def top_rules(db: Session, *, start: datetime, end: datetime, severity: str | None = None, limit: int = 10) -> list[dict[str, Any]]:
    statement = (
        select(Alert.rule, func.count().label("count"))
        .where(Alert.created_at >= start, Alert.created_at < end)
    )
    if severity:
        statement = statement.where(Alert.severity == severity)
    statement = statement.group_by(Alert.rule).order_by(func.count().desc(), Alert.rule).limit(limit)
    return _rows(db, statement)


def top_source_ips(db: Session, *, start: datetime, end: datetime, severity: str | None = None, limit: int = 10) -> list[dict[str, Any]]:
    ip_text = func.host(Alert.source_ip).label("source_ip")
    statement = (
        select(ip_text, func.count().label("count"))
        .where(Alert.created_at >= start, Alert.created_at < end, Alert.source_ip.is_not(None))
    )
    if severity:
        statement = statement.where(Alert.severity == severity)
    statement = statement.group_by(ip_text).order_by(func.count().desc(), ip_text).limit(limit)
    return _rows(db, statement)


def alerts_raised_count(db: Session, *, start: datetime, end: datetime, severity: str | None = None) -> int:
    statement = select(func.count()).select_from(Alert).where(Alert.created_at >= start, Alert.created_at < end)
    if severity:
        statement = statement.where(Alert.severity == severity)
    return db.scalar(statement) or 0


def most_active_rules(db: Session, *, start: datetime, end: datetime, limit: int = 10) -> list[dict[str, Any]]:
    statement = (
        select(Alert.rule, func.count().label("count"))
        .where(Alert.created_at >= start, Alert.created_at < end)
        .group_by(Alert.rule)
        .order_by(func.count().desc(), Alert.rule)
        .limit(limit)
    )
    return _rows(db, statement)


def rules_with_hits(db: Session, *, start: datetime, end: datetime) -> set[str]:
    statement = (
        select(Alert.rule)
        .where(Alert.created_at >= start, Alert.created_at < end)
        .distinct()
    )
    return {row[0] for row in db.execute(statement).all()}


# --------------------------------------------------------------------------
# Incident-based aggregates (Weekly incident summary, Executive overview)
# --------------------------------------------------------------------------


def incidents_over_time_by_priority(
    db: Session, *, start: datetime, end: datetime, tz_name: str, unit: BucketUnit, priority: str | None = None,
) -> list[dict[str, Any]]:
    bucket = _bucket(Incident.opened_at, tz_name, unit).label("bucket")
    statement = (
        select(bucket, Incident.priority, func.count().label("count"))
        .where(Incident.opened_at >= start, Incident.opened_at < end)
    )
    if priority:
        statement = statement.where(Incident.priority == priority)
    statement = statement.group_by(bucket, Incident.priority).order_by(bucket)
    return _rows(db, statement)


def incidents_by_rule(db: Session, *, start: datetime, end: datetime, priority: str | None = None, limit: int = 15) -> list[dict[str, Any]]:
    statement = (
        select(Alert.rule, func.count().label("count"))
        .select_from(Incident)
        .join(Alert, Alert.id == Incident.source_alert_id)
        .where(Incident.opened_at >= start, Incident.opened_at < end)
    )
    if priority:
        statement = statement.where(Incident.priority == priority)
    statement = statement.group_by(Alert.rule).order_by(func.count().desc(), Alert.rule).limit(limit)
    return _rows(db, statement)


def incidents_opened_count(db: Session, *, start: datetime, end: datetime, priority: str | None = None) -> int:
    statement = select(func.count()).select_from(Incident).where(Incident.opened_at >= start, Incident.opened_at < end)
    if priority:
        statement = statement.where(Incident.priority == priority)
    return db.scalar(statement) or 0


def incidents_closed_count(db: Session, *, start: datetime, end: datetime, priority: str | None = None) -> int:
    statement = (
        select(func.count())
        .select_from(Incident)
        .where(
            Incident.resolved_at.is_not(None),
            Incident.resolved_at >= start,
            Incident.resolved_at < end,
            Incident.status.in_(("RESOLVED", "FALSE_POSITIVE")),
        )
    )
    if priority:
        statement = statement.where(Incident.priority == priority)
    return db.scalar(statement) or 0


def time_to_resolve_by_priority(db: Session, *, start: datetime, end: datetime) -> list[dict[str, Any]]:
    """Resolution-time stats for incidents resolved within the window, by priority."""

    seconds = _resolve_seconds(Incident.opened_at, Incident.resolved_at)
    statement = (
        select(
            Incident.priority,
            func.count().label("count"),
            func.avg(seconds).label("avg_seconds"),
            func.percentile_cont(0.5).within_group(seconds).label("median_seconds"),
        )
        .where(
            Incident.resolved_at.is_not(None),
            Incident.resolved_at >= start,
            Incident.resolved_at < end,
        )
        .group_by(Incident.priority)
        .order_by(Incident.priority)
    )
    return _rows(db, statement)


def overall_resolution_stats(db: Session, *, start: datetime, end: datetime) -> dict[str, Any]:
    seconds = _resolve_seconds(Incident.opened_at, Incident.resolved_at)
    statement = select(
        func.count().label("count"),
        func.avg(seconds).label("avg_seconds"),
        func.percentile_cont(0.5).within_group(seconds).label("median_seconds"),
    ).where(
        Incident.resolved_at.is_not(None),
        Incident.resolved_at >= start,
        Incident.resolved_at < end,
    )
    row = db.execute(statement).one()
    return dict(row._mapping)


def incidents_in_range(
    db: Session, *, start: datetime, end: datetime, priority: str | None = None, limit: int,
) -> tuple[list[dict[str, Any]], int]:
    assignee = aliased(User)
    assignee_label = _assignee_label(assignee.full_name, assignee.username)

    base = (
        select(
            Incident.id,
            Incident.title,
            Incident.priority,
            Incident.status,
            Incident.opened_at,
            Incident.resolved_at,
            Alert.rule,
            Alert.hostname,
            Alert.username,
            assignee_label.label("assignee"),
        )
        .select_from(Incident)
        .join(Alert, Alert.id == Incident.source_alert_id)
        .outerjoin(assignee, assignee.id == Incident.assigned_user_id)
        .where(Incident.opened_at >= start, Incident.opened_at < end)
    )
    if priority:
        base = base.where(Incident.priority == priority)

    count_stmt = select(func.count()).select_from(base.with_only_columns(Incident.id).subquery())
    rows_stmt = base.order_by(Incident.opened_at.desc(), Incident.id.desc())
    return _count_and_limited(db, count_stmt, rows_stmt, limit)


def most_affected_hosts(db: Session, *, start: datetime, end: datetime, limit: int = 10) -> list[dict[str, Any]]:
    statement = (
        select(Alert.hostname, func.count(func.distinct(Incident.id)).label("count"))
        .select_from(Incident)
        .join(Alert, Alert.id == Incident.source_alert_id)
        .where(Incident.opened_at >= start, Incident.opened_at < end, Alert.hostname.is_not(None))
        .group_by(Alert.hostname)
        .order_by(func.count(func.distinct(Incident.id)).desc(), Alert.hostname)
        .limit(limit)
    )
    return _rows(db, statement)


def most_affected_users(db: Session, *, start: datetime, end: datetime, limit: int = 10) -> list[dict[str, Any]]:
    statement = (
        select(Alert.username, func.count(func.distinct(Incident.id)).label("count"))
        .select_from(Incident)
        .join(Alert, Alert.id == Incident.source_alert_id)
        .where(Incident.opened_at >= start, Incident.opened_at < end, Alert.username.is_not(None))
        .group_by(Alert.username)
        .order_by(func.count(func.distinct(Incident.id)).desc(), Alert.username)
        .limit(limit)
    )
    return _rows(db, statement)


def incidents_per_assignee(db: Session, *, start: datetime, end: datetime, priority: str | None = None) -> list[dict[str, Any]]:
    assignee_label = _assignee_label(User.full_name, User.username)
    statement = (
        select(assignee_label.label("assignee"), func.count().label("count"))
        .select_from(Incident)
        .outerjoin(User, User.id == Incident.assigned_user_id)
        .where(Incident.opened_at >= start, Incident.opened_at < end)
    )
    if priority:
        statement = statement.where(Incident.priority == priority)
    statement = statement.group_by(assignee_label).order_by(func.count().desc())
    return _rows(db, statement)


def open_high_critical_incidents(db: Session, *, limit: int) -> tuple[list[dict[str, Any]], int]:
    assignee_label = _assignee_label(User.full_name, User.username)
    base = (
        select(
            Incident.id,
            Incident.title,
            Incident.priority,
            Incident.status,
            Incident.opened_at,
            assignee_label.label("assignee"),
        )
        .select_from(Incident)
        .outerjoin(User, User.id == Incident.assigned_user_id)
        .where(
            Incident.status.in_(("OPEN", "INVESTIGATING")),
            Incident.priority.in_(("HIGH", "CRITICAL")),
        )
    )
    count_stmt = select(func.count()).select_from(base.with_only_columns(Incident.id).subquery())
    rows_stmt = base.order_by(Incident.priority.desc(), Incident.opened_at)
    return _count_and_limited(db, count_stmt, rows_stmt, limit)


# --------------------------------------------------------------------------
# Detection rule catalog (Detection coverage)
# --------------------------------------------------------------------------


def rule_catalog_status(db: Session) -> list[dict[str, Any]]:
    """Every built-in DetectionEngine rule with its effective lifecycle state.

    Status is one of "Enabled", "Shadow mode", or "Disabled". Shadow mode is
    a rule-level `params.shadow_mode` flag (see app/detection/rules/base.py)
    on top of the enabled/disabled toggle, not a separate database field.
    """

    configs = effective_rule_configs(db, settings.detection_rule_config)
    rows: list[dict[str, Any]] = []
    for rule_cls in _RULE_CLASSES:
        rule = rule_cls()
        config = configs[rule.name]
        if not config.enabled:
            status = "Disabled"
        elif (config.params or {}).get("shadow_mode") is True:
            status = "Shadow mode"
        else:
            status = "Enabled"
        rows.append({
            "name": rule.name,
            "mitre_technique": rule.mitre_technique or None,
            "status": status,
        })
    return rows


def mitre_coverage(db: Session) -> list[dict[str, Any]]:
    """Enabled, non-shadow rules grouped by the MITRE technique they cover."""

    by_technique: dict[str, list[str]] = {}
    for row in rule_catalog_status(db):
        if row["status"] != "Enabled" or not row["mitre_technique"]:
            continue
        by_technique.setdefault(row["mitre_technique"], []).append(row["name"])
    return [
        {"technique": technique, "rules": sorted(names)}
        for technique, names in sorted(by_technique.items())
    ]


def rules_with_no_hits(db: Session, *, start: datetime, end: datetime) -> list[str]:
    """Enabled rule names that raised no alert at all in the window."""

    active_names = {row["name"] for row in rule_catalog_status(db) if row["status"] != "Disabled"}
    hit_names = rules_with_hits(db, start=start, end=end)
    return sorted(active_names - hit_names)


# --------------------------------------------------------------------------
# Host heartbeat health (Daily SOC operations, Detection coverage)
# --------------------------------------------------------------------------


def host_heartbeat_status(db: Session, *, now: datetime) -> list[dict[str, Any]]:
    """Every host's current reporting status (host_heartbeats is one row per
    host, so this is a small dimension table — unlike alerts/incidents, it's
    fine to hold the full set in Python; the caller caps rows for display.
    """

    from app.detection.engine import DetectionEngine
    from app.detection.rules.host_log_silence import HostLogSilenceRule

    configs = effective_rule_configs(db, settings.detection_rule_config)
    config = configs[HostLogSilenceRule.name]
    # Mirror GET /detection/host-heartbeats: reporting health is informational
    # even when the alerting rule itself is turned off, so fall back to the
    # class defaults rather than hiding every host's status.
    rule = DetectionEngine.rule_from_config(HostLogSilenceRule, config) or HostLogSilenceRule()

    statement = select(HostHeartbeat).order_by(HostHeartbeat.hostname)
    rows = []
    for heartbeat in db.scalars(statement).all():
        last_seen = heartbeat.last_seen_at if heartbeat.last_seen_at.tzinfo else heartbeat.last_seen_at.replace(tzinfo=now.tzinfo)
        threshold = rule.silence_threshold(heartbeat.cadence_seconds)
        silent_for = max(0.0, (now - last_seen).total_seconds())
        if heartbeat.event_count < int(rule.params["min_events"]):
            host_status = "Learning"
        elif silent_for > threshold:
            host_status = "Silent"
        else:
            host_status = "Reporting"
        rows.append({
            "hostname": heartbeat.hostname,
            "status": host_status,
            "last_seen_at": last_seen,
            "event_count": heartbeat.event_count,
        })
    return rows
