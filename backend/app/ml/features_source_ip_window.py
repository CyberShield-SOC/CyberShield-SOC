"""
Feature extraction for per-source-IP behavior windows (Sprint 6 KK-05 / PBI-26).

Aggregation unit: one source IP x one fixed five-minute (300 s) UTC window.
Windows are *tumbling* and half-open, ``[start, start + 300)``, anchored to the
Unix epoch, so a given event always lands in the same window no matter what else
was uploaded. This deliberately differs from the correlation engine's windows
(anchored at the first event, inclusive at both ends): correlation answers "which
events belong together as evidence", while model features need a stable grid that
produces identical rows on every run.

Inputs are normalized ``LogRecord`` objects (see ``records_from_logs`` for stored
database rows), never raw free text. Everything here is a pure function of the
input records: the same stored events always give the same vectors, in the same
order, with the same float values (rounded to 6 places so serialization is stable).

Why there is no "unique source IPs" feature: the aggregation key *is* the source
IP, so that count would be the constant 1 in every row. A per-window unique-IP
count only becomes meaningful if the unit changes (e.g. per host), at which point
this module's key function is the only thing that needs to change.

Missing-value policy (applied uniformly, never left to the model):

* Records with no parseable timestamp or no valid source IP cannot be assigned to
  a window. They are dropped and counted in ``ExtractionReport`` -- never guessed.
* Counts of things not seen are 0.
* ``failed_to_success_ratio`` is ``failed / (success + 1)``: smoothed so it is
  always finite and a window with no logins is exactly 0.0.
* ``mean_gap_seconds`` / ``min_gap_seconds`` need two events. A single-event window
  gets ``window_seconds`` for both ("no gap shorter than the window observed").
* Parser-quality ratios are over the records used in that window, which is always
  at least one, so they are always defined.
"""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from ipaddress import ip_address
from typing import Iterable

from app.detection.models import LogRecord
from app.repositories.log_repository import parse_event_timestamp

FEATURE_SET = "source_ip_window"
ENTITY_TYPE = "source_ip"
WINDOW_SECONDS = 300

# Order matters: this is the exact column order every vector uses.
FEATURE_NAMES: tuple[str, ...] = (
    "event_count",
    "failed_login_count",
    "success_login_count",
    "failed_to_success_ratio",
    "unique_users",
    "unique_hosts",
    "sudo_failure_count",
    "mean_gap_seconds",
    "min_gap_seconds",
    "hour_sin",
    "hour_cos",
    "known_status_ratio",
    "known_event_type_ratio",
)

_UNKNOWN_TEXT = {"", "unknown", "-", "none", "null"}
_GENERIC_EVENT_TYPES = {"", "security_event", "unknown"}
_PRECISION = 6


@dataclass(frozen=True)
class WindowFeatures:
    """One model-ready row: a source IP's behavior inside one window."""

    entity_id: str
    window_start: datetime
    window_end: datetime
    features: dict[str, float]
    upload_ids: tuple[str, ...]
    record_count: int

    def vector(self, names: tuple[str, ...] = FEATURE_NAMES) -> list[float]:
        return [float(self.features[name]) for name in names]

    def snapshot_kwargs(self) -> dict:
        """Arguments for ``save_feature_snapshot`` (MLFeatureSnapshot compatible)."""

        return {
            "feature_set": FEATURE_SET,
            "entity_type": ENTITY_TYPE,
            "entity_id": self.entity_id,
            "captured_at": self.window_start,
            "features": dict(self.features),
        }


@dataclass(frozen=True)
class ExtractionReport:
    total_records: int
    used_records: int
    duplicate_records: int
    dropped_missing_timestamp: int
    dropped_invalid_ip: int
    windows: int


def _identity(record: LogRecord) -> tuple:
    if record.log_id is not None:
        return ("log", record.log_id)
    return ("line", record.upload_id, record.line_number)


def _canonical_ip(value: str | None) -> str | None:
    if value is None or value.strip().lower() in _UNKNOWN_TEXT:
        return None
    try:
        return str(ip_address(value.strip()))
    except ValueError:
        return None


def _norm(value: str | None) -> str:
    return (value or "").strip().lower()


def _round(value: float) -> float:
    return round(float(value), _PRECISION) + 0.0  # + 0.0 turns -0.0 into 0.0


def _window_start(timestamp: datetime, window_seconds: int) -> datetime:
    epoch = int(timestamp.timestamp())
    return datetime.fromtimestamp(epoch - epoch % window_seconds, tz=timezone.utc)


def _features_for(
    entries: list[tuple[datetime, LogRecord]], start: datetime, window_seconds: int
) -> dict[str, float]:
    records = [record for _, record in entries]
    failed = success = sudo_failed = known_status = known_type = 0
    for record in records:
        status, event_type = _norm(record.status), _norm(record.event_type)
        if event_type == "login_attempt" and status == "failed":
            failed += 1
        elif event_type == "login_attempt" and status == "success":
            success += 1
        if event_type == "privilege_escalation" and status == "failed":
            sudo_failed += 1
        known_status += status in {"success", "failed"}
        known_type += event_type not in _GENERIC_EVENT_TYPES

    times = [ts.timestamp() for ts, _ in entries]  # already sorted ascending
    gaps = [later - earlier for earlier, later in zip(times, times[1:])]
    mean_gap = sum(gaps) / len(gaps) if gaps else float(window_seconds)
    min_gap = min(gaps) if gaps else float(window_seconds)

    hour = start.hour + start.minute / 60
    count = len(records)
    values = {
        "event_count": count,
        "failed_login_count": failed,
        "success_login_count": success,
        "failed_to_success_ratio": failed / (success + 1),
        "unique_users": len({_norm(r.username) for r in records} - _UNKNOWN_TEXT),
        "unique_hosts": len({_norm(r.hostname).rstrip(".") for r in records} - _UNKNOWN_TEXT),
        "sudo_failure_count": sudo_failed,
        "mean_gap_seconds": mean_gap,
        "min_gap_seconds": min_gap,
        "hour_sin": math.sin(2 * math.pi * hour / 24),
        "hour_cos": math.cos(2 * math.pi * hour / 24),
        "known_status_ratio": known_status / count,
        "known_event_type_ratio": known_type / count,
    }
    return {name: _round(values[name]) for name in FEATURE_NAMES}


def extract_window_features(
    records: Iterable[LogRecord], *, window_seconds: int = WINDOW_SECONDS
) -> tuple[list[WindowFeatures], ExtractionReport]:
    """Turn normalized events into deterministic per-(source IP, window) rows.

    Output is sorted by (window_start, entity_id). Duplicate records (same
    ``log_id``, or same upload+line when no id exists) are counted once.
    """

    if window_seconds < 1:
        raise ValueError("window_seconds must be at least 1")

    seen: set[tuple] = set()
    buckets: dict[tuple[str, datetime], list[tuple[datetime, LogRecord]]] = defaultdict(list)
    total = duplicates = no_time = bad_ip = 0

    for record in records:
        total += 1
        key = _identity(record)
        if key in seen:
            duplicates += 1
            continue
        seen.add(key)
        timestamp = parse_event_timestamp(record.timestamp)
        if timestamp is None:
            no_time += 1
            continue
        entity = _canonical_ip(record.ip_address)
        if entity is None:
            bad_ip += 1
            continue
        timestamp = timestamp.astimezone(timezone.utc)
        buckets[(entity, _window_start(timestamp, window_seconds))].append((timestamp, record))

    rows: list[WindowFeatures] = []
    for (entity, start), entries in buckets.items():
        entries.sort(key=lambda item: (item[0], item[1].upload_id or "", item[1].line_number))
        rows.append(
            WindowFeatures(
                entity_id=entity,
                window_start=start,
                window_end=datetime.fromtimestamp(start.timestamp() + window_seconds, tz=timezone.utc),
                features=_features_for(entries, start, window_seconds),
                upload_ids=tuple(sorted({r.upload_id for _, r in entries if r.upload_id})),
                record_count=len(entries),
            )
        )
    rows.sort(key=lambda row: (row.window_start, row.entity_id))

    report = ExtractionReport(
        total_records=total,
        used_records=total - duplicates - no_time - bad_ip,
        duplicate_records=duplicates,
        dropped_missing_timestamp=no_time,
        dropped_invalid_ip=bad_ip,
        windows=len(rows),
    )
    return rows, report


def records_from_logs(logs: Iterable) -> list[LogRecord]:
    """Stored ``Log`` rows -> normalized records, via the same normalizer the
    correlation service uses, so features never read raw free text."""

    from app.repositories.correlation_repository import normalized_log

    return [
        normalized_log(log).model_copy(update={"log_id": log.id, "upload_id": str(log.upload_id)})
        for log in logs
    ]
