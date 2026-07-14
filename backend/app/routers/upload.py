import uuid
from datetime import datetime, timezone

from fastapi import (
    APIRouter,
    Depends,
    File,
    HTTPException,
    UploadFile,
)
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.detection import DetectionEngine
from app.detection.alert_store import serialize_alert
from app.detection.models import LogRecord
from app.middleware.file_validation import validate_log_file
from app.parsers.log_parser import parse_log
from app.repositories.alert_repository import (
    create_alerts_from_detection,
    serialize_alert_record,
)
from app.repositories.log_repository import (
    create_logs_from_parse_result,
)


_engine = DetectionEngine()

router = APIRouter(tags=["Upload"])


@router.post("/upload")
async def upload_log(
    logfile: UploadFile = File(
        ...,
        description="Security log file (.log, .csv)",
    ),
    db: Session = Depends(get_db),
):
    """
    Accept a security log file, validate it, parse it,
    run detection rules, and store logs and alerts.
    """

    # --- Read file content ---
    content_bytes = await logfile.read()

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


@router.get("/upload/formats", tags=["Upload"])
def get_accepted_formats():
    """Return accepted file types and usage information."""

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
        ],
        "note": (
            "Detection rules run over parsed entries "
            "and persistent alerts are stored in PostgreSQL."
        ),
    }