"""Deterministic, rule-scoped correlation of exact supporting event identities.

Windows are anchored at their first event and inclusive at both boundaries.
Repeated event references are deduplicated; distinct source rows are retained.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from hashlib import sha256
from ipaddress import ip_address
import json
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from app.detection.models import LogRecord
from app.repositories.log_repository import parse_event_timestamp

Entity = Literal["source_ip", "account", "host", "upload_batch"]
SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


class EvidenceEvent(BaseModel):
    id: int = Field(gt=0)
    upload_id: str
    record: LogRecord


class EvidenceAlert(BaseModel):
    id: int = Field(gt=0)
    rule: str
    event_ids: tuple[int, ...]
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    confidence: int | None = Field(default=None, ge=0, le=100)
    policy_key: str | None = None


class CorrelationPolicy(BaseModel):
    rule_key: str
    entity_type: Entity
    window_seconds: int = Field(default=600, ge=1)
    minimum_events: int = Field(default=1, ge=1)
    cross_upload: bool = False
    version: int = Field(default=1, ge=1)
    rule_context: dict = Field(default_factory=dict)


class CorrelationResult(BaseModel):
    model_config = ConfigDict(frozen=True)
    fingerprint: str
    group_type: str = "rule_entity_window"
    entity_type: Entity
    entity_value: str
    first_seen: datetime
    last_seen: datetime
    window_seconds: int
    severity: str
    confidence: int | None
    reason: str
    rule_key: str
    rule_context: dict
    event_ids: tuple[int, ...]
    alert_ids: tuple[int, ...]
    upload_ids: tuple[str, ...]


def _entity(event: EvidenceEvent, entity_type: Entity) -> str | None:
    if entity_type == "upload_batch":
        return event.upload_id
    field = {"source_ip": "ip_address", "account": "username", "host": "hostname"}[
        entity_type
    ]
    value = getattr(event.record, field)
    if not value or value.strip().lower() in {"unknown", "-"}:
        return None
    value = value.strip()
    if entity_type == "source_ip":
        try:
            return str(ip_address(value))
        except ValueError:
            return None
    return value.rstrip(".").lower() if entity_type == "host" else value


def _unique(items):
    result = {}
    for item in items:
        if item.id in result and item != result[item.id]:
            raise ValueError(f"Conflicting evidence identity {item.id}.")
        result[item.id] = item
    return result


def correlate(
    events: list[EvidenceEvent],
    alerts: list[EvidenceAlert],
    policies: dict[str, CorrelationPolicy],
) -> list[CorrelationResult]:
    event_by_id = _unique(events)
    alert_by_id = _unique(alerts)
    partitions = defaultdict(dict)
    memberships = defaultdict(lambda: defaultdict(set))
    for alert in sorted(alert_by_id.values(), key=lambda item: item.id):
        policy_key = alert.policy_key or alert.rule
        policy = policies.get(policy_key)
        if policy is None:
            continue
        if policy.rule_key != alert.rule:
            raise ValueError("Correlation policy must match its rule key.")
        for event_id in set(alert.event_ids):
            event = event_by_id.get(event_id)
            if event is None:
                continue
            entity = _entity(event, policy.entity_type)
            timestamp = parse_event_timestamp(event.record.timestamp)
            if entity is None or timestamp is None:
                continue
            scope = "cross_upload" if policy.cross_upload else event.upload_id
            key = (policy_key, policy.entity_type, entity, scope)
            partitions[key][event.id] = (event, timestamp)
            memberships[key][event.id].add(alert.id)

    results = []
    for key in sorted(partitions):
        policy_key, entity_type, entity_value, _ = key
        policy = policies[policy_key]
        rule = policy.rule_key
        ordered = sorted(
            partitions[key].values(), key=lambda pair: (pair[1], pair[0].id)
        )
        bucket = []

        def emit():
            if len(bucket) < policy.minimum_events:
                return
            event_ids = tuple(sorted(event.id for event, _ in bucket))
            alert_ids = tuple(
                sorted({aid for eid in event_ids for aid in memberships[key][eid]})
            )
            upload_ids = tuple(sorted({event.upload_id for event, _ in bucket}))
            context = {
                "policy": policy.model_dump(mode="json"),
                "boundary": "inclusive",
                "confidence_aggregation": "maximum_source_confidence",
            }
            identity = {
                "context": context,
                "entity": [entity_type, entity_value],
                "events": event_ids,
                "alerts": alert_ids,
                "uploads": upload_ids,
            }
            fingerprint = sha256(
                json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            sources = [alert_by_id[aid] for aid in alert_ids]
            confidences = [a.confidence for a in sources if a.confidence is not None]
            span = (bucket[-1][1] - bucket[0][1]).total_seconds()
            results.append(
                CorrelationResult(
                    fingerprint=fingerprint,
                    entity_type=entity_type,
                    entity_value=entity_value,
                    first_seen=bucket[0][1],
                    last_seen=bucket[-1][1],
                    window_seconds=policy.window_seconds,
                    severity=max(
                        (a.severity for a in sources), key=SEVERITY_ORDER.__getitem__
                    ),
                    confidence=max(confidences) if confidences else None,
                    reason=f"Same {entity_type} {entity_value}; {rule} policy v{policy.version}; {len(event_ids)} supporting events spanning {span:g}s within an inclusive {policy.window_seconds}s window.",
                    rule_key=rule,
                    rule_context=context,
                    event_ids=event_ids,
                    alert_ids=alert_ids,
                    upload_ids=upload_ids,
                )
            )

        for item in ordered:
            if (
                bucket
                and (item[1] - bucket[0][1]).total_seconds() > policy.window_seconds
            ):
                emit()
                bucket = []
            bucket.append(item)
        emit()
    return results
