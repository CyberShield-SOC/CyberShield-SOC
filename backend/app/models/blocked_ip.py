from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import Boolean, DateTime, Index, Integer, String, Text, UniqueConstraint, func, text
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

class BlockedIp(Base):
    """Network-level IP blocking tracker (active defense log)."""
    
    __tablename__ = "blocked_ips"
    
    __table_args__ = (
        Index("ix_blocked_ips_ip", "ip", unique=True),
    )
    
    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )
    
    ip: Mapped[str] = mapped_column(
        INET,
        nullable=False,
        unique=True,
    )
    
    rule_name: Mapped[str] = mapped_column(
        String(150),
        nullable=False,
    )
    
    reason: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default=text("true"),
    )
    
    block_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
        server_default=text("1"),
    )
    
    unblock_reason: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )
    
    unblocked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )
    
    created_by: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )
    
    updated_by: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )
