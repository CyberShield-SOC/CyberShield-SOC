from typing import Literal

import anthropic
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.assistant.service import (
    AssistantUnavailableError,
    AssistantUpstreamError,
    get_client,
    run_chat,
)
from app.assistant.tools import MAX_HOURS
from app.db.session import get_db
from app.models.assistant_message import AssistantMessage
from app.models.user import User
from app.security import require_roles

router = APIRouter(tags=["Assistant"])

MAX_MESSAGES = 20
MAX_MESSAGE_CHARS = 4000
SAVED_HISTORY_LIMIT = 100


class ChatMessage(BaseModel):
    role: Literal["user", "assistant"]
    content: str = Field(min_length=1, max_length=MAX_MESSAGE_CHARS)


class ChatRequest(BaseModel):
    messages: list[ChatMessage] = Field(min_length=1, max_length=MAX_MESSAGES)
    time_range_hours: int = Field(default=24, ge=1, le=MAX_HOURS)

    @field_validator("messages")
    @classmethod
    def must_end_with_user_turn(cls, messages: list[ChatMessage]) -> list[ChatMessage]:
        if messages[0].role != "user" or messages[-1].role != "user":
            raise ValueError("The conversation must start and end with a user message.")
        return messages


def get_assistant_client() -> anthropic.Anthropic:
    try:
        return get_client()
    except AssistantUnavailableError as exc:
        raise HTTPException(status_code=503, detail="The AI assistant is not configured.") from exc


@router.post("/assistant/chat")
def assistant_chat(
    payload: ChatRequest,
    user: User = Depends(require_roles("Admin", "Analyst", "Viewer")),
    db: Session = Depends(get_db),
    client: anthropic.Anthropic = Depends(get_assistant_client),
):
    """Answer an analyst question using read-only workspace data tools.

    The assistant can only read: it has no tool that changes alerts, incidents,
    users, blocklists or settings. Tools are limited to what the caller's role
    may already read through the REST API.
    """

    try:
        result = run_chat(
            client,
            db=db,
            user=user,
            messages=[message.model_dump() for message in payload.messages],
            time_range_hours=payload.time_range_hours,
        )
    except AssistantUpstreamError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc

    return {
        "success": True,
        "reply": result.reply,
        "model": result.model,
        "tools_used": result.tools_used,
    }


class SavedMessage(BaseModel):
    role: Literal["user", "assistant"]
    content: str = Field(min_length=1, max_length=MAX_MESSAGE_CHARS)
    tools_used: list[str] = Field(default_factory=list, max_length=50)

    @field_validator("content")
    @classmethod
    def content_not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Message content cannot be blank.")
        return value


def _serialize_saved_message(row: AssistantMessage) -> dict:
    return {
        "id": row.id,
        "role": row.role,
        "content": row.body,
        "tools_used": list(row.tools_used or []),
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


@router.get("/assistant/messages")
def list_saved_messages(
    user: User = Depends(require_roles("Admin", "Analyst", "Viewer")),
    db: Session = Depends(get_db),
):
    """Return the caller's most recent saved assistant messages, oldest first."""
    rows = db.scalars(
        select(AssistantMessage)
        .where(AssistantMessage.user_id == user.id)
        .order_by(AssistantMessage.id.desc())
        .limit(SAVED_HISTORY_LIMIT)
    ).all()
    return {"success": True, "messages": [_serialize_saved_message(row) for row in reversed(rows)]}


@router.post("/assistant/messages", status_code=201)
def save_message(
    payload: SavedMessage,
    user: User = Depends(require_roles("Admin", "Analyst", "Viewer")),
    db: Session = Depends(get_db),
):
    """Save one message to the caller's assistant conversation."""
    row = AssistantMessage(
        user_id=user.id,
        role=payload.role,
        body=payload.content.strip(),
        tools_used=payload.tools_used,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return {"success": True, "message": _serialize_saved_message(row)}


@router.delete("/assistant/messages")
def clear_saved_messages(
    user: User = Depends(require_roles("Admin", "Analyst", "Viewer")),
    db: Session = Depends(get_db),
):
    """Delete the caller's saved assistant conversation."""
    db.execute(delete(AssistantMessage).where(AssistantMessage.user_id == user.id))
    db.commit()
    return {"success": True}
