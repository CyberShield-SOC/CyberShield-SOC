import uuid
from fastapi import (
    APIRouter,
    Depends,
    File,
    HTTPException,
    Query,
    UploadFile,
)
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from sqlalchemy import func, or_, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.session import get_db
from app.detection import DetectionEngine
from app.detection.alert_store import serialize_alert
from app.detection.geoip import enrich_records, get_geo_resolver
from app.detection.normalize import log_record_from_entry
from app.detection.rules.custom_condition import CustomConditionRule
from app.middleware.file_validation import MAX_FILE_SIZE_BYTES, validate_log_file
from app.models.alert import Alert
from app.models.log import Log
from app.models.upload_batch import UploadBatch
from app.models.user import User
from app.parsers.log_parser import parse_log
from app.repositories.blocked_ip_repository import auto_block_from_alerts
from app.repositories.alert_repository import (
    create_alerts_from_detection,
    serialize_alert_record,
    suppress_alerts_in_cooldown,
)
from app.repositories.custom_rule_action_repository import apply_custom_rule_actions
from app.repositories.custom_rule_repository import list_enabled_custom_rules
from app.repositories.detection_rule_setting_repository import effective_rule_configs
from app.repositories.log_repository import (
    create_logs_from_parse_result,
)
from app.repositories.upload_batch_repository import (
    create_upload_batch,
    serialize_upload_batch,
)
from app.security import require_roles


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
        "port": log.port,
        "raw_message": log.raw_message,
    }


def build_upload_batch_payload(
    db: Session,
    upload_id: uuid.UUID,
) -> dict | None:
    """Load one persisted upload batch using the dashboard response shape."""

    batch = db.get(UploadBatch, upload_id)
    if batch is None:
        return None

    stored_logs = list(
        db.scalars(
            select(Log)
            .where(Log.upload_id == upload_id)
            .order_by(Log.line_number.asc())
        ).all()
    )

    stored_alerts = list(
        db.scalars(
            select(Alert)
            .where(Alert.upload_id == upload_id)
            .order_by(Alert.created_at.asc(), Alert.id.asc())
        ).all()
    )

    return {
        "success": True,
        "upload": serialize_upload_batch(batch),
        "logs": [serialize_log_for_dashboard(log) for log in stored_logs],
        "alerts": [serialize_alert_record(alert) for alert in stored_alerts],
    }


def _run_upload_pipeline(
    db: Session,
    *,
    content_bytes: bytes,
    source_filename: str,
    mime_type: str | None,
) -> dict:
    """
    Decode, parse, run detection, and persist one uploaded file.

    This is CPU-bound (decode + regex parsing + rule evaluation over
    potentially hundreds of thousands of lines) and makes synchronous DB
    calls throughout, so the route handler runs it via run_in_threadpool
    instead of inline on the async event loop — otherwise a single large
    upload would stall every other concurrent request until it finished.
    """

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
    records = enrich_records(
        [log_record_from_entry(entry, str(parsed["format"])) for entry in parsed["entries"]],
        get_geo_resolver(),
    )

    configs = effective_rule_configs(db, settings.detection_rule_config)
    engine = DetectionEngine.from_config({name: config.model_dump() for name, config in configs.items()})
    alerts = engine.run(records, db)

    enabled_custom_rules = list_enabled_custom_rules(db)
    custom_rule_titles: dict[str, str] = {}
    for custom_rule in enabled_custom_rules:
        if not custom_rule.actions.get("create_alert", False):
            continue
        runner = CustomConditionRule(
            rule_id=custom_rule.rule_id,
            display_name=custom_rule.name,
            severity=custom_rule.severity,
            conditions=custom_rule.conditions,
            group_by=custom_rule.group_by,
            window_seconds=custom_rule.window_seconds,
        )
        custom_rule_titles[custom_rule.rule_id] = custom_rule.name
        alerts.extend(runner.analyze(records))

    cooldown_by_rule = {name: config.cooldown_seconds for name, config in configs.items()}
    alerts = suppress_alerts_in_cooldown(db, alerts, cooldown_by_rule)

    def _serialize(alert):
        data = serialize_alert(alert)
        if alert.rule in custom_rule_titles:
            data["title"] = custom_rule_titles[alert.rule]
        return data

    serialized_alerts = [_serialize(alert) for alert in alerts]

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

        active_defense_summary = auto_block_from_alerts(db, saved_alerts)
        # This whole pipeline already runs off the event loop (see
        # upload_log below), so the Slack dispatch inside
        # apply_custom_rule_actions can stay a plain call here.
        custom_rule_action_summary = apply_custom_rule_actions(
            db,
            alerts=saved_alerts,
            custom_rules=enabled_custom_rules,
            slack_webhook_url=settings.slack_webhook_url,
        )

        batch = create_upload_batch(
            db,
            upload_id=upload_id,
            source_filename=source_filename,
            source_format=str(parsed["format"]),
            mime_type=mime_type,
            size_bytes=len(content_bytes),
            total_lines=int(parsed["total_lines"]),
            parsed_entries=len(parsed["entries"]),
            skipped_lines=len(parsed["skipped_lines"]),
            stored_entries=len(saved_logs),
            stored_alerts=len(saved_alerts),
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
    return {
        "success": True,
        "upload": serialize_upload_batch(batch),
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
        "active_defense": active_defense_summary,
        "custom_rule_actions": custom_rule_action_summary,
    }


@router.post("/upload")
async def upload_log(
    logfile: UploadFile = File(
        ...,
        description="Security log file (.log, .csv, .txt, .json, .jsonl)",
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

    # --- Validate (also strips any path components from the filename) ---
    source_filename = validate_log_file(logfile, content_bytes)

    payload = await run_in_threadpool(
        _run_upload_pipeline,
        db,
        content_bytes=content_bytes,
        source_filename=source_filename,
        mime_type=logfile.content_type,
    )

    return JSONResponse(status_code=200, content=payload)


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
        select(UploadBatch.upload_id)
        .order_by(
            UploadBatch.uploaded_at.desc(),
            UploadBatch.upload_id.desc(),
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
            UploadBatch.source_filename.ilike(pattern, escape="\\"),
            UploadBatch.source_format.ilike(pattern, escape="\\"),
        )

    total_statement = select(func.count(UploadBatch.upload_id))
    if search_filter is not None:
        total_statement = total_statement.where(search_filter)
    total = int(db.scalar(total_statement) or 0)
    statement = (
        select(
            UploadBatch,
        )
    )
    if search_filter is not None:
        statement = statement.where(search_filter)
    statement = (
        statement
        .order_by(UploadBatch.uploaded_at.desc(), UploadBatch.upload_id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    batches = list(db.scalars(statement).all())

    return {
        "success": True,
        "uploads": [
            serialize_upload_batch(batch)
            for batch in batches
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
        "max_file_size_mb": MAX_FILE_SIZE_BYTES // 1024 // 1024,
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
                "extension": ".txt",
                "description": (
                    "Plain-text log lines, or delimiter-separated exports "
                    "with a header row (parsed the same way as .csv when "
                    "delimited content is detected)"
                ),
                "example": "access_logs.txt",
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
