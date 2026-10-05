from __future__ import annotations

from collections import defaultdict
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.detection.normalize import log_record_from_entry
from app.models.correlation import (
    AlertEventLink,
    CorrelationGroup,
    CorrelationGroupAlert,
    CorrelationGroupEvent,
    CorrelationGroupUpload,
)
from app.models.log import Log
from app.services.correlation import (
    CorrelationPolicy,
    EvidenceAlert,
    EvidenceEvent,
    correlate,
)


def save_results(db: Session, results):
    groups = []
    for result in results:
        values = result.model_dump(exclude={"event_ids", "alert_ids", "upload_ids"})
        identity = db.scalar(
            insert(CorrelationGroup)
            .values(**values)
            .on_conflict_do_nothing(index_elements=["fingerprint"])
            .returning(CorrelationGroup.id)
        )
        if identity is None:
            identity = db.scalar(
                select(CorrelationGroup.id).where(
                    CorrelationGroup.fingerprint == result.fingerprint
                )
            )
        for model, column, items in (
            (CorrelationGroupEvent, "log_id", result.event_ids),
            (CorrelationGroupAlert, "alert_id", result.alert_ids),
            (
                CorrelationGroupUpload,
                "upload_id",
                [UUID(value) for value in result.upload_ids],
            ),
        ):
            if items:
                db.execute(
                    insert(model)
                    .values([{"group_id": identity, column: item} for item in items])
                    .on_conflict_do_nothing()
                )
        groups.append(db.get(CorrelationGroup, identity))
    db.flush()
    return groups


def correlate_upload(db, *, logs, alerts, serialized_alerts, rule_contexts):
    """Link exact detection evidence and persist correlation inside caller's transaction."""
    by_line = {log.line_number: log.id for log in logs}
    linked_ids = defaultdict(set)
    policies = {}
    policy_keys = {}
    for alert, output in zip(alerts, serialized_alerts, strict=True):
        lines = set(output.get("matched_line_numbers") or [])
        references = set(output.get("matched_event_ids") or [])
        existing_ids = (
            set(db.scalars(select(Log.id).where(Log.id.in_(references))).all())
            if references
            else set()
        )
        linked_ids[alert.id].update(by_line[line] for line in lines if line in by_line)
        linked_ids[alert.id].update(existing_ids)
        missing = len(lines - by_line.keys()) + len(references - existing_ids)
        provenance = {
            "missing_references": missing,
            "expected_events": alert.event_count,
            "linked_events": len(linked_ids[alert.id]),
            "complete": missing == 0 and len(linked_ids[alert.id]) >= alert.event_count,
        }
        alert.evidence = {**alert.evidence, "provenance": provenance}
        if linked_ids[alert.id]:
            db.execute(
                insert(AlertEventLink)
                .values(
                    [
                        {"alert_id": alert.id, "log_id": eid}
                        for eid in sorted(linked_ids[alert.id])
                    ]
                )
                .on_conflict_do_nothing()
            )
        context = rule_contexts.get(alert.rule)
        if context is not None:
            entity = (
                alert.entity_type
                if context.get("kind") == "builtin"
                else context["correlation_entity"]
            )
            key = f"{alert.rule}:{entity}"
            policy_keys[alert.id] = key
            policies[key] = CorrelationPolicy(
                rule_key=alert.rule,
                entity_type=entity,
                window_seconds=context.get("correlation_window_seconds")
                or max(1, alert.time_window_seconds or 600),
                cross_upload=context.get("cross_upload", False),
                rule_context=context,
            )
    all_ids = {eid for ids in linked_ids.values() for eid in ids}
    stored_logs = (
        list(db.scalars(select(Log).where(Log.id.in_(all_ids))).all())
        if all_ids
        else []
    )
    events = [
        EvidenceEvent(
            id=log.id, upload_id=str(log.upload_id), record=normalized_log(log)
        )
        for log in stored_logs
    ]
    sources = [
        EvidenceAlert(
            id=alert.id,
            rule=alert.rule,
            policy_key=policy_keys.get(alert.id),
            event_ids=tuple(sorted(linked_ids[alert.id])),
            severity=alert.severity,
            confidence=alert.confidence,
        )
        for alert in alerts
    ]
    db.flush()
    return save_results(db, correlate(events, sources, policies))


def normalized_log(log):
    return log_record_from_entry(
        {"line_number": log.line_number, "parsed": log.parsed_data}, log.source_format
    )


def serialize_event(log):
    return {
        "id": log.id,
        "upload_id": str(log.upload_id),
        "line_number": log.line_number,
        "source_filename": log.source_filename,
        "source_format": log.source_format,
        "event_timestamp": log.event_timestamp.isoformat()
        if log.event_timestamp
        else None,
        "ingested_at": log.ingested_at.isoformat(),
        "raw_message": log.raw_message,
        "normalized": normalized_log(log).model_dump(mode="json"),
        "parsed_data": log.parsed_data,
    }


def group_payloads(db, groups):
    ids = [g.id for g in groups]
    counts = defaultdict(dict)
    for model, label in (
        (CorrelationGroupEvent, "events"),
        (CorrelationGroupAlert, "alerts"),
        (CorrelationGroupUpload, "uploads"),
    ):
        for identity, count in db.execute(
            select(model.group_id, func.count())
            .where(model.group_id.in_(ids))
            .group_by(model.group_id)
        ):
            counts[identity][label] = count
    return [
        {
            "id": g.id,
            "group_type": g.group_type,
            "entity_type": g.entity_type,
            "entity_value": g.entity_value,
            "first_seen": g.first_seen.isoformat(),
            "last_seen": g.last_seen.isoformat(),
            "window_seconds": g.window_seconds,
            "severity": g.severity,
            "confidence": g.confidence,
            "reason": g.reason,
            "rule_key": g.rule_key,
            "created_at": g.created_at.isoformat(),
            "counts": {
                label: counts[g.id].get(label, 0)
                for label in ("events", "alerts", "uploads")
            },
        }
        for g in groups
    ]


def paginate(db, statement, *, page, page_size):
    total = (
        db.scalar(select(func.count()).select_from(statement.order_by(None).subquery()))
        or 0
    )
    items = list(
        db.scalars(statement.offset((page - 1) * page_size).limit(page_size)).all()
    )
    return items, {
        "page": page,
        "page_size": page_size,
        "total": total,
        "page_count": max(1, (total + page_size - 1) // page_size),
    }
