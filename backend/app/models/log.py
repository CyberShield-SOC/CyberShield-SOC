from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    BigInteger,
    DateTime,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class Log(Base):
    """A parsed security event stored by CyberShield."""

    __tablename__ = "logs"

    __table_args__ = (
        UniqueConstraint(
            "upload_id",
            "line_number",
            name="uq_logs_upload_line_number",
        ),
        Index("ix_logs_upload_id", "upload_id"),
        Index("ix_logs_event_timestamp", "event_timestamp"),
        Index("ix_logs_ip_address", "ip_address"),
        Index("ix_logs_username", "username"),
        Index("ix_logs_event_type", "event_type"),
        Index("ix_logs_status", "status"),
    )

    id: Mapped[int] = mapped_column(
        BigInteger,
        primary_key=True,
        autoincrement=True,
    )

    upload_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        nullable=False,
    )

    source_filename: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    source_format: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )

    line_number: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    event_timestamp: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    ip_address: Mapped[str | None] = mapped_column(
        INET,
        nullable=True,
    )

    username: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    event_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        server_default=text("'security_event'"),
    )

    status: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        server_default=text("'UNKNOWN'"),
    )

    severity: Mapped[str | None] = mapped_column(
        String(30),
        nullable=True,
    )

    raw_message: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    parsed_data: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )

    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    def __repr__(self) -> str:
        return (
            f"Log(id={self.id!r}, "
            f"upload_id={self.upload_id!r}, "
            f"line_number={self.line_number!r}, "
            f"event_type={self.event_type!r})"
        )