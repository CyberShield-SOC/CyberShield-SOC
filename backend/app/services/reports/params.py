"""Validate and resolve the from/to/range/severity query parameters shared by
every report. Raises ValueError on anything the router should turn into a
422 — never an HTTPException directly, so this stays testable without FastAPI.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Literal

from app.core.config import settings

ReportRangePreset = Literal["24h", "7d", "30d"]

_PRESET_DURATIONS: dict[ReportRangePreset, timedelta] = {
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
}


@dataclass(frozen=True)
class ReportRange:
    start: datetime
    end: datetime
    previous_start: datetime
    previous_end: datetime


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def resolve_report_range(
    *,
    range_preset: ReportRangePreset | None,
    from_: datetime | None,
    to: datetime | None,
    now: datetime | None = None,
) -> ReportRange:
    """Resolve the effective [start, end) window and its comparison period.

    Exactly one of a preset range or an explicit from/to pair may be given.
    With neither, defaults to the 24h preset.
    """

    if range_preset is not None and (from_ is not None or to is not None):
        raise ValueError("Provide either `range` or `from`/`to`, not both.")

    if (from_ is None) != (to is None):
        raise ValueError("`from` and `to` must be provided together.")

    now = _as_utc(now) if now is not None else datetime.now(timezone.utc)

    if from_ is not None and to is not None:
        start, end = _as_utc(from_), _as_utc(to)
        if end <= start:
            raise ValueError("`to` must be after `from`.")
    else:
        preset = range_preset or "24h"
        if preset not in _PRESET_DURATIONS:
            raise ValueError(f"Unsupported range preset '{preset}'.")
        end = now
        start = end - _PRESET_DURATIONS[preset]

    max_span = timedelta(days=settings.report_max_range_days)
    if end - start > max_span:
        raise ValueError(
            f"The selected range exceeds the {settings.report_max_range_days}-day maximum."
        )

    span = end - start
    return ReportRange(
        start=start,
        end=end,
        previous_start=start - span,
        previous_end=start,
    )
