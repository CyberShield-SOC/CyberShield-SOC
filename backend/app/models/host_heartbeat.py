from __future__ import annotations

from datetime import datetime

from sqlalchemy import BigInteger, DateTime, Float, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class HostHeartbeat(Base):
    """
    Last-known reporting state for one host, updated on every upload that
    contains events from it. host_log_silence compares these rows against a
    reference time to find hosts that stopped sending logs.
    """

    __tablename__ = "host_heartbeats"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    event_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # Smoothed 90th-percentile gap between consecutive events, in seconds —
    # the host's normal reporting cadence. NULL until enough events are seen.
    cadence_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)
    # last_seen_at value a silence alert was already raised for, so one
    # silence episode produces one alert no matter how often it's checked.
    silence_alerted_for: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )

    def __repr__(self) -> str:
        return f"HostHeartbeat(hostname={self.hostname!r}, last_seen_at={self.last_seen_at!r})"
