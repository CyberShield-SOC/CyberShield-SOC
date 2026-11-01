"""Turn a repository's (bucket, group, count) rows into chart series."""

from __future__ import annotations

from datetime import datetime


def pivot_time_series(
    rows: list[dict], *, group_key: str, bucket_key: str = "bucket", value_key: str = "count",
) -> tuple[list[datetime], dict[str, list[float]]]:
    buckets = sorted({row[bucket_key] for row in rows})
    index = {bucket: position for position, bucket in enumerate(buckets)}
    series: dict[str, list[float]] = {}
    for row in rows:
        values = series.setdefault(row[group_key], [0.0] * len(buckets))
        values[index[row[bucket_key]]] = float(row[value_key])
    return buckets, series


def bucket_unit_for_span(span_seconds: float) -> str:
    return "hour" if span_seconds <= 2 * 24 * 3600 else "day"


def label_bucket(value: datetime, unit: str) -> str:
    return value.strftime("%b %d %H:%M") if unit == "hour" else value.strftime("%b %d")
