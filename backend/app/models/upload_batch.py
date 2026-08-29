from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import BigInteger, DateTime, Index, Integer, String, func, text
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class UploadBatch(Base):
    """Authoritative metadata for one uploaded log file."""

    __tablename__ = "upload_batches"

    __table_args__ = (
        Index("ix_upload_batches_uploaded_at", "uploaded_at"),
        Index("ix_upload_batches_source_filename", "source_filename"),
        Index("ix_upload_batches_source_format", "source_format"),
    )

    upload_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
    )

    source_filename: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    source_format: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )

    mime_type: Mapped[str | None] = mapped_column(
        String(150),
        nullable=True,
    )

    size_bytes: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
    )

    total_lines: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        server_default=text("0"),
    )

    parsed_entries: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        server_default=text("0"),
    )

    skipped_lines: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        server_default=text("0"),
    )

    stored_entries: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        server_default=text("0"),
    )

    stored_alerts: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        server_default=text("0"),
    )

    uploaded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    def __repr__(self) -> str:
        return (
            f"UploadBatch(upload_id={self.upload_id!r}, "
            f"source_filename={self.source_filename!r}, "
            f"stored_entries={self.stored_entries!r})"
        )
