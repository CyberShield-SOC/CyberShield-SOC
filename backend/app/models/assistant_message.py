from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class AssistantMessage(Base):
    """One saved message in an analyst's AI assistant conversation."""

    __tablename__ = "assistant_messages"

    __table_args__ = (
        CheckConstraint("role IN ('user', 'assistant')", name="ck_assistant_messages_role"),
        CheckConstraint("char_length(btrim(body)) > 0", name="ck_assistant_messages_body_not_blank"),
        Index("ix_assistant_messages_user_id_id", "user_id", "id"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)

    user_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )

    role: Mapped[str] = mapped_column(String(10), nullable=False)

    body: Mapped[str] = mapped_column(Text, nullable=False)

    tools_used: Mapped[list[str]] = mapped_column(
        ARRAY(String(100)),
        nullable=False,
        default=list,
        server_default=text("'{}'"),
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
