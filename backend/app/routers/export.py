"""Standards-based exports: events and alerts as ECS NDJSON."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Callable, Iterable, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.alert import Alert
from app.models.log import Log
from app.models.user import User
from app.security import require_roles
from app.services.audit import record_audit
from app.services.ecs import ECS_VERSION, EXPORT_ROW_LIMIT, alert_to_ecs, event_to_ecs

router = APIRouter(tags=["Export"])

_CHUNK_ROWS = 1000


def _ndjson_chunks(rows: Iterable, to_document: Callable) -> tuple[list[bytes], int, bool]:
    """Serialise rows to NDJSON in chunks, stopping at the export cap.

    The documents are built here, while the database session is certainly
    open, and only the encoded bytes are handed to the response.
    """

    chunks: list[bytes] = []
    lines: list[str] = []
    count = 0
    truncated = False
    for row in rows:
        if count >= EXPORT_ROW_LIMIT:
            truncated = True
            break
        lines.append(json.dumps(to_document(row), separators=(",", ":"), ensure_ascii=False))
        count += 1
        if len(lines) >= _CHUNK_ROWS:
            chunks.append(("\n".join(lines) + "\n").encode("utf-8"))
            lines = []
    if lines:
        chunks.append(("\n".join(lines) + "\n").encode("utf-8"))
    return chunks, count, truncated


def _response(chunks: list[bytes], *, name: str, count: int, truncated: bool) -> StreamingResponse:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return StreamingResponse(
        iter(chunks),
        media_type="application/x-ndjson",
        headers={
            "Content-Disposition": f'attachment; filename="cybershield-{name}-ecs-{stamp}.ndjson"',
            "X-ECS-Version": ECS_VERSION,
            "X-Export-Count": str(count),
            "X-Export-Truncated": "true" if truncated else "false",
            "Access-Control-Expose-Headers": "Content-Disposition, X-ECS-Version, X-Export-Count, X-Export-Truncated",
        },
    )


@router.get("/events/export")
def export_events(
    request: Request,
    format: Literal["ecs"] = Query(default="ecs"),
    upload_id: UUID | None = Query(default=None),
    from_: datetime | None = Query(default=None, alias="from"),
    to: datetime | None = Query(default=None),
    user: User = Depends(require_roles("Admin", "Analyst")),
    db: Session = Depends(get_db),
):
    """Stored events as ECS documents, one JSON object per line (NDJSON).

    Capped at 50,000 rows, oldest first; ``X-Export-Truncated`` says when the
    cap cut the result short, so narrow the filters and export again.
    """

    statement = select(
        Log.id, Log.upload_id, Log.source_filename, Log.source_format, Log.line_number,
        Log.event_timestamp, Log.event_type, Log.status, Log.severity, Log.raw_message,
        Log.parsed_data, Log.ingested_at,
    )
    if upload_id is not None:
        statement = statement.where(Log.upload_id == upload_id)
    if from_ is not None:
        statement = statement.where(Log.event_timestamp >= from_)
    if to is not None:
        statement = statement.where(Log.event_timestamp <= to)
    statement = statement.order_by(Log.id).limit(EXPORT_ROW_LIMIT + 1)

    rows = db.execute(statement.execution_options(yield_per=_CHUNK_ROWS))
    chunks, count, truncated = _ndjson_chunks(rows, event_to_ecs)

    record_audit(
        db,
        request,
        action="export.events",
        actor=user,
        target_type="upload" if upload_id else "events",
        target_id=str(upload_id) if upload_id else None,
        detail={"format": format, "count": count, "truncated": truncated},
    )
    db.commit()
    return _response(chunks, name="events", count=count, truncated=truncated)


@router.get("/alerts/export")
def export_alerts(
    request: Request,
    format: Literal["ecs"] = Query(default="ecs"),
    upload_id: UUID | None = Query(default=None),
    from_: datetime | None = Query(default=None, alias="from"),
    to: datetime | None = Query(default=None),
    user: User = Depends(require_roles("Admin", "Analyst")),
    db: Session = Depends(get_db),
):
    """Stored alerts as ECS alert documents (NDJSON), oldest first."""

    statement = select(Alert)
    if upload_id is not None:
        statement = statement.where(Alert.upload_id == upload_id)
    if from_ is not None:
        statement = statement.where(Alert.created_at >= from_)
    if to is not None:
        statement = statement.where(Alert.created_at <= to)
    statement = statement.order_by(Alert.id).limit(EXPORT_ROW_LIMIT + 1)

    chunks, count, truncated = _ndjson_chunks(db.scalars(statement), alert_to_ecs)

    record_audit(
        db,
        request,
        action="export.alerts",
        actor=user,
        target_type="alerts",
        target_id=str(upload_id) if upload_id else None,
        detail={"format": format, "count": count, "truncated": truncated},
    )
    db.commit()
    return _response(chunks, name="alerts", count=count, truncated=truncated)
