"""Derived correlation results reference, but never own, source evidence."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.alert import Alert
from app.models.log import Log


class CorrelationGroup(Base):
    __tablename__ = "correlation_groups"
    __table_args__ = (
        CheckConstraint(
            "entity_type IN ('source_ip','account','host','upload_batch')",
            name="ck_correlation_entity_type",
        ),
        CheckConstraint(
            "last_seen >= first_seen", name="ck_correlation_observation_order"
        ),
        CheckConstraint("window_seconds > 0", name="ck_correlation_window"),
        CheckConstraint(
            "confidence IS NULL OR confidence BETWEEN 0 AND 100",
            name="ck_correlation_confidence",
        ),
        CheckConstraint(
            "severity IN ('LOW','MEDIUM','HIGH','CRITICAL')",
            name="ck_correlation_severity",
        ),
        Index("ix_correlation_entity", "entity_type", "entity_value"),
        Index("ix_correlation_first_seen", "first_seen", "id"),
        Index("ix_correlation_rule_key", "rule_key"),
    )
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    group_type: Mapped[str] = mapped_column(String(100), nullable=False)
    entity_type: Mapped[str] = mapped_column(String(20), nullable=False)
    entity_value: Mapped[str] = mapped_column(String(255), nullable=False)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    window_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    confidence: Mapped[int | None] = mapped_column(Integer)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    rule_key: Mapped[str] = mapped_column(String(100), nullable=False)
    rule_context: Mapped[dict] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    events: Mapped[list[CorrelationGroupEvent]] = relationship(
        cascade="all, delete-orphan", passive_deletes=True
    )
    alerts: Mapped[list[CorrelationGroupAlert]] = relationship(
        cascade="all, delete-orphan", passive_deletes=True
    )
    uploads: Mapped[list[CorrelationGroupUpload]] = relationship(
        cascade="all, delete-orphan", passive_deletes=True
    )


class CorrelationGroupEvent(Base):
    __tablename__ = "correlation_group_events"
    __table_args__ = (Index("ix_correlation_events_log", "log_id"),)
    group_id: Mapped[int] = mapped_column(
        ForeignKey("correlation_groups.id", ondelete="CASCADE"), primary_key=True
    )
    log_id: Mapped[int] = mapped_column(
        ForeignKey("logs.id", ondelete="RESTRICT"), primary_key=True
    )
    log: Mapped[Log] = relationship()


class CorrelationGroupAlert(Base):
    __tablename__ = "correlation_group_alerts"
    __table_args__ = (Index("ix_correlation_alerts_alert", "alert_id"),)
    group_id: Mapped[int] = mapped_column(
        ForeignKey("correlation_groups.id", ondelete="CASCADE"), primary_key=True
    )
    alert_id: Mapped[int] = mapped_column(
        ForeignKey("alerts.id", ondelete="RESTRICT"), primary_key=True
    )
    alert: Mapped[Alert] = relationship()


class CorrelationGroupUpload(Base):
    __tablename__ = "correlation_group_uploads"
    __table_args__ = (Index("ix_correlation_uploads_upload", "upload_id"),)
    group_id: Mapped[int] = mapped_column(
        ForeignKey("correlation_groups.id", ondelete="CASCADE"), primary_key=True
    )
    upload_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("upload_batches.upload_id", ondelete="RESTRICT"),
        primary_key=True,
    )


class AlertEventLink(Base):
    __tablename__ = "alert_event_links"
    __table_args__ = (Index("ix_alert_event_links_log", "log_id"),)
    alert_id: Mapped[int] = mapped_column(
        ForeignKey("alerts.id", ondelete="RESTRICT"), primary_key=True
    )
    log_id: Mapped[int] = mapped_column(
        ForeignKey("logs.id", ondelete="RESTRICT"), primary_key=True
    )
