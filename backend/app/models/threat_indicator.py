from __future__ import annotations

from datetime import datetime

from sqlalchemy import BigInteger, CheckConstraint, DateTime, ForeignKey, Index, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class ThreatIndicator(Base):
    """
    One indicator (IP, CIDR range, or domain) imported from a named threat
    intelligence feed. The feed itself is whatever an Admin/Analyst imports
    through /threat-intel/feeds — no provider is built in. Re-importing a
    feed with replace=true swaps that source's whole indicator set.
    """

    __tablename__ = "threat_indicators"

    __table_args__ = (
        CheckConstraint(
            "indicator_type IN ('ip', 'cidr', 'domain')",
            name="ck_threat_indicators_type",
        ),
        Index("ux_threat_indicators_source_value", "source", "indicator", unique=True),
        Index("ix_threat_indicators_indicator", "indicator"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    source: Mapped[str] = mapped_column(String(100), nullable=False)
    indicator: Mapped[str] = mapped_column(String(255), nullable=False)
    indicator_type: Mapped[str] = mapped_column(String(10), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    def __repr__(self) -> str:
        return f"ThreatIndicator(source={self.source!r}, indicator={self.indicator!r})"
