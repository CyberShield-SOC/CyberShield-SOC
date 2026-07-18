import uuid
from datetime import datetime, timezone

from fastapi import (
    APIRouter,
    Depends,
    File,
    HTTPException,
    Query,
    UploadFile,
)
from fastapi.responses import JSONResponse

from sqlalchemy import func, or_, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.detection import DetectionEngine
from app.detection.alert_store import serialize_alert
from app.detection.models import LogRecord
from app.middleware.file_validation import MAX_FILE_SIZE_BYTES, validate_log_file
from app.models.alert import Alert
from app.models.log import Log
from app.models.user import User
from app.parsers.log_parser import parse_log
from app.repositories.alert_repository import (
    create_alerts_from_detection,
    serialize_alert_record,
)
from app.repositories.log_repository import (
    create_logs_from_parse_result,
)
from app.security import require_roles


_engine = DetectionEngine()

router = APIRouter(tags=["Upload"])

def serialize_log_for_dashboard(log: Log) -> dict:
    """
    Convert a stored Log model into the structure expected
    by the existing React dashboard.
    """

    parsed_data = log.parsed_data or {}

    timestamp = parsed_data.get("timestamp")

    if not timestamp and log.event_timestamp:
        timestamp = log.event_timestamp.isoformat()

    return {
        "id": log.id,
        "upload_id": str(log.upload_id),
        "line_number": log.line_number,
        "source_filename": log.source_filename,
        "source_format": log.source_format,
        "timestamp": timestamp or "",
        "ingested_at": log.ingested_at.isoformat(),
        "ip": (
            str(log.ip_address)
            if log.ip_address is not None
            else ""
        ),
        "username": log.username or "",
        "event": log.event_type or "Log Entry",
        "status": (log.status or "UNKNOWN").upper(),
        "severity": (log.severity or "INFO").upper(),
        "raw_message": log.raw_message,
    }


def build_upload_batch_payload(
    db: Session,
    upload_id: uuid.UUID,
) -> dict | None:
    """Load one persisted upload batch using the dashboard response shape."""

    stored_logs = list(
        db.scalars(
            select(Log)
            .where(Log.upload_id == upload_id)
            .order_by(Log.line_number.asc())
        ).all()
    )
    if not stored_logs:
        return None

    stored_alerts = list(
        db.scalars(
            select(Alert)
            .where(Alert.upload_id == upload_id)
            .order_by(Alert.created_at.asc(), Alert.id.asc())
        ).all()
    )
    first_log = stored_logs[0]
    uploaded_at = max(log.ingested_at for log in stored_logs)

    return {
        "success": True,
        "upload": {
            "upload_id": str(upload_id),
            "filename": first_log.source_filename,
            "format": first_log.source_format,
            "uploaded_at": uploaded_at.isoformat(),
            "stored_entries": len(stored_logs),
            "stored_alerts": len(stored_alerts),
        },
        "logs": [serialize_log_for_dashboard(log) for log in stored_logs],
        "alerts": [serialize_alert_record(alert) for alert in stored_alerts],
    }


@router.post("/upload")
async def upload_log(
    logfile: UploadFile = File(
        ...,
        description="Security log file (.log, .csv, .json, .jsonl)",
    ),
    user: User = Depends(require_roles("Admin", "Analyst")),
    db: Session = Depends(get_db),
):
    """
    Accept a security log file, validate it, parse it,
    run detection rules, and store logs and alerts.
    """

    # --- Read file content ---
    # Read one byte past the limit so oversized files are rejected without
    # loading an unbounded request body into application memory.
    content_bytes = await logfile.read(MAX_FILE_SIZE_BYTES + 1)

    # --- Validate ---
    validate_log_file(logfile, content_bytes)

    # --- Decode ---
    try:
        content_str = content_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HTTPException(
            status_code=400,
            detail={
                "success": False,
                "error": (
                    "File could not be decoded as UTF-8. "
                    "Please upload a plain text log file."
                ),
                "code": "ENCODING_ERROR",
            },
        ) from exc

    # --- Parse ---
    source_filename = logfile.filename or "unknown.log"

    parsed = parse_log(
        content_str,
        source_filename,
    )

    if not parsed["entries"]:
        raise HTTPException(
            status_code=422,
            detail={
                "success": False,
                "error": "No security events could be parsed. Verify the file structure and field names.",
                "code": "NO_PARSEABLE_EVENTS",
                "skipped_lines": len(parsed["skipped_lines"]),
            },
        )

    upload_id = uuid.uuid4()

    # --- Run detection engine ---
    records = [
        LogRecord(
            line_number=entry["line_number"],
            timestamp=entry["parsed"].get("timestamp"),
            ip_address=entry["parsed"].get("ip_address") or None,
            username=entry["parsed"].get("username") or None,
            event_type=entry["parsed"].get("event_type"),
            status=entry["parsed"].get("status"),
        )
        for entry in parsed["entries"]
    ]

    alerts = _engine.run(records)

    serialized_alerts = [
        serialize_alert(alert)
        for alert in alerts
    ]

    # --- Store logs and alerts in one transaction ---
    try:
        saved_logs = create_logs_from_parse_result(
            db,
            upload_id=upload_id,
            source_filename=source_filename,
            parsed_result=parsed,
        )

        saved_alerts = create_alerts_from_detection(
            db,
            upload_id=upload_id,
            serialized_alerts=serialized_alerts,
        )

        db.commit()

        response_alerts = [
            serialize_alert_record(alert)
            for alert in saved_alerts
        ]

    except SQLAlchemyError as exc:
        db.rollback()

        raise HTTPException(
            status_code=500,
            detail={
                "success": False,
                "error": (
                    "Parsed logs and alerts could not be stored."
                ),
                "code": "DATABASE_WRITE_ERROR",
            },
        ) from exc

    # --- Build response ---
    return JSONResponse(
        status_code=200,
        content={
            "success": True,
            "upload": {
                "upload_id": str(upload_id),
                "filename": source_filename,
                "mime_type": logfile.content_type,
                "size_bytes": len(content_bytes),
                "uploaded_at": datetime.now(
                    timezone.utc
                ).isoformat(),
            },
            "parsing": {
                "format": parsed["format"],
                "total_lines": parsed["total_lines"],
                "parsed_entries": len(parsed["entries"]),
                "stored_entries": len(saved_logs),
                "stored_alerts": len(saved_alerts),
                "skipped_lines": len(parsed["skipped_lines"]),
                "fields": parsed["fields"],
            },
            "entries": parsed["entries"],
            "skipped_lines": parsed["skipped_lines"],
            "alerts": response_alerts,
        },
    )


@router.get("/upload/latest")
def get_latest_upload(
    user: User = Depends(require_roles("Admin", "Analyst", "Viewer")),
    db: Session = Depends(get_db),
):
    """
    Return the logs and alerts belonging only to the
    most recently uploaded file.
    """

    latest_upload_id = db.scalar(
        select(Log.upload_id)
        .order_by(
            Log.ingested_at.desc(),
            Log.id.desc(),
        )
        .limit(1)
    )

    if latest_upload_id is None:
        return {
            "success": True,
            "upload": None,
            "logs": [],
            "alerts": [],
        }

    return build_upload_batch_payload(db, latest_upload_id)


@router.get("/upload/history")
def get_upload_history(
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    query: str | None = Query(None, max_length=100),
    user: User = Depends(require_roles("Admin", "Analyst", "Viewer")),
    db: Session = Depends(get_db),
):
    """Return paginated metadata for every persisted upload batch."""

    search = (query or "").strip()
    search_filter = None
    if search:
        # Treat user input literally so SQL wildcard characters cannot turn a
        # narrow filename search into an unexpectedly broad database scan.
        escaped = (
            search.replace("\\", "\\\\")
            .replace("%", "\\%")
            .replace("_", "\\_")
        )
        pattern = f"%{escaped}%"
        search_filter = or_(
            Log.source_filename.ilike(pattern, escape="\\"),
            Log.source_format.ilike(pattern, escape="\\"),
        )

    total_statement = select(func.count(func.distinct(Log.upload_id)))
    if search_filter is not None:
        total_statement = total_statement.where(search_filter)
    total = int(db.scalar(total_statement) or 0)
    alert_counts = (
        select(
            Alert.upload_id.label("upload_id"),
            func.count(Alert.id).label("stored_alerts"),
        )
        .group_by(Alert.upload_id)
        .subquery()
    )
    uploaded_at = func.max(Log.ingested_at).label("uploaded_at")
    statement = (
        select(
            Log.upload_id,
            Log.source_filename,
            Log.source_format,
            uploaded_at,
            func.count(Log.id).label("stored_entries"),
            func.coalesce(alert_counts.c.stored_alerts, 0).label("stored_alerts"),
        )
        .outerjoin(
            alert_counts,
            alert_counts.c.upload_id == Log.upload_id,
        )
    )
    if search_filter is not None:
        statement = statement.where(search_filter)
    statement = (
        statement
        .group_by(
            Log.upload_id,
            Log.source_filename,
            Log.source_format,
            alert_counts.c.stored_alerts,
        )
        .order_by(uploaded_at.desc(), Log.upload_id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    rows = db.execute(statement).all()

    return {
        "success": True,
        "uploads": [
            {
                "upload_id": str(row.upload_id),
                "filename": row.source_filename,
                "format": row.source_format,
                "uploaded_at": row.uploaded_at.isoformat(),
                "stored_entries": int(row.stored_entries or 0),
                "stored_alerts": int(row.stored_alerts or 0),
            }
            for row in rows
        ],
        "pagination": {
            "page": page,
            "page_size": page_size,
            "total": total,
            "page_count": max(1, (total + page_size - 1) // page_size),
        },
    }


@router.get("/upload/batches/{upload_id}")
def get_upload_batch(
    upload_id: uuid.UUID,
    user: User = Depends(require_roles("Admin", "Analyst", "Viewer")),
    db: Session = Depends(get_db),
):
    """Return the normalized events and alerts for one persisted upload."""

    payload = build_upload_batch_payload(db, upload_id)
    if payload is None:
        raise HTTPException(
            status_code=404,
            detail="That uploaded file no longer exists.",
        )
    return payload


@router.get("/upload/formats", tags=["Upload"])
def get_accepted_formats(
    user: User = Depends(require_roles("Admin", "Analyst", "Viewer")),
):
    """Returns accepted file types and usage guide."""
    return {
        "success": True,
        "field_name": "logfile",
        "max_file_size_mb": 10,
        "accepted_formats": [
            {
                "extension": ".log",
                "description": (
                    "Generic, syslog, Apache, or Nginx-style log files"
                ),
                "example": "/var/log/auth.log",
            },
            {
                "extension": ".csv",
                "description": (
                    "Comma-separated log exports with header row"
                ),
                "example": "access_logs.csv",
            },
            {
                "extension": ".json",
                "description": (
                    "JSON arrays, objects, or common event containers"
                ),
                "example": "security_events.json",
            },
            {
                "extension": ".jsonl",
                "description": (
                    "Newline-delimited JSON security events"
                ),
                "example": "events.jsonl",
            },
        ],
        "note": (
            "Detection rules run over parsed entries "
            "and persistent alerts are stored in PostgreSQL."
        ),
    }
