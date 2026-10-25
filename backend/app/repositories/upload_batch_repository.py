from __future__ import annotations

from uuid import UUID

from sqlalchemy.orm import Session

from app.models.upload_batch import UploadBatch


def create_upload_batch(
    db: Session,
    *,
    upload_id: UUID,
    source_filename: str,
    source_format: str,
    mime_type: str | None,
    size_bytes: int,
    total_lines: int,
    parsed_entries: int,
    skipped_lines: int,
    stored_entries: int,
    stored_alerts: int,
    source_name: str | None = None,
    source_type: str | None = None,
    source_host: str | None = None,
    ingested_by: int | None = None,
) -> UploadBatch:
    """Create one upload-batch metadata row inside the caller's transaction."""

    batch = UploadBatch(
        upload_id=upload_id,
        source_filename=source_filename,
        source_format=source_format,
        mime_type=mime_type,
        size_bytes=size_bytes,
        total_lines=total_lines,
        parsed_entries=parsed_entries,
        skipped_lines=skipped_lines,
        stored_entries=stored_entries,
        stored_alerts=stored_alerts,
        source_name=source_name,
        source_type=source_type,
        source_host=source_host,
        ingested_by=ingested_by,
    )
    db.add(batch)
    db.flush()
    return batch


def serialize_upload_batch(batch: UploadBatch) -> dict:
    """Return the stable upload metadata shape consumed by the API."""

    return {
        "upload_id": str(batch.upload_id),
        "filename": batch.source_filename,
        "format": batch.source_format,
        "mime_type": batch.mime_type,
        "size_bytes": batch.size_bytes,
        "uploaded_at": batch.uploaded_at.isoformat(),
        "total_lines": batch.total_lines,
        "parsed_entries": batch.parsed_entries,
        "skipped_lines": batch.skipped_lines,
        "stored_entries": batch.stored_entries,
        "stored_alerts": batch.stored_alerts,
        "source_name": batch.source_name,
        "source_type": batch.source_type,
        "source_host": batch.source_host,
        "ingested_by": batch.ingested_by,
    }
