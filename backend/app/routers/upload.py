import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, File, HTTPException, UploadFile
from fastapi.responses import JSONResponse

from app.detection import DetectionEngine
from app.detection.alert_store import replace_alerts
from app.detection.models import Alert, LogRecord
from app.middleware.file_validation import validate_log_file
from app.parsers.log_parser import parse_log

_engine = DetectionEngine()

router = APIRouter(tags=["Upload"])


@router.post("/upload")
async def upload_log(logfile: UploadFile = File(..., description="Security log file (.log, .csv)")):
    """
    Accepts a security log file, validates it, parses it,
    runs detection rules, and returns structured JSON for the frontend.
    """

    content_bytes = await logfile.read()
    validate_log_file(logfile, content_bytes)

    try:
        content_str = content_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(
            status_code=400,
            detail={
                "success": False,
                "error": "File could not be decoded as UTF-8. Please upload a plain text log file.",
                "code": "ENCODING_ERROR",
            },
        )

    parsed = parse_log(content_str, logfile.filename or "unknown.log")

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
    alerts = [_serialize_alert(alert) for alert in _engine.run(records)]
    replace_alerts(alerts)

    return JSONResponse(
        status_code=200,
        content={
            "success": True,
            "upload": {
                "upload_id": str(uuid.uuid4()),
                "filename": logfile.filename,
                "mime_type": logfile.content_type,
                "size_bytes": len(content_bytes),
                "uploaded_at": datetime.now(timezone.utc).isoformat(),
            },
            "parsing": {
                "format": parsed["format"],
                "total_lines": parsed["total_lines"],
                "parsed_entries": len(parsed["entries"]),
                "skipped_lines": len(parsed["skipped_lines"]),
                "fields": parsed["fields"],
            },
            "detection": {
                "rules_run": [rule.__class__.__name__ for rule in _engine.rules],
                "alerts_generated": len(alerts),
            },
            "entries": parsed["entries"],
            "skipped_lines": parsed["skipped_lines"],
            "alerts": alerts,
        },
    )


@router.get("/upload/formats", tags=["Upload"])
def get_accepted_formats():
    """Returns accepted file types and usage guide."""
    return {
        "success": True,
        "field_name": "logfile",
        "max_file_size_mb": 10,
        "accepted_formats": [
            {
                "extension": ".log",
                "description": "Generic, syslog, Apache, or Nginx-style log files",
                "example": "/var/log/auth.log",
            },
            {
                "extension": ".csv",
                "description": "Comma-separated log exports with header row",
                "example": "access_logs.csv",
            },
        ],
        "note": "Detection rules run automatically over parsed entries.",
    }


def _serialize_alert(alert: Alert) -> dict:
    data = alert.model_dump()
    data.update(
        {
            "title": _title_for_rule(alert.rule),
            "ip_address": alert.source_ip,
            "user": alert.username,
            "reason": alert.description,
            "timestamp_range": {
                "start": alert.first_seen,
                "end": alert.last_seen,
            },
        }
    )
    return data


def _title_for_rule(rule: str) -> str:
    labels = {
        "brute_force_login": "Possible brute-force login activity",
        "invalid_user_enumeration": "Possible username enumeration",
        "sudo_failure": "Repeated sudo authentication failures",
    }
    return labels.get(rule, "Security alert")
