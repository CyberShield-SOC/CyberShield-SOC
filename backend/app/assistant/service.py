from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any

import anthropic
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.assistant.prompts import build_system_prompt
from app.assistant.tools import ToolContext, ToolInputError, run_tool, tools_for, utcnow
from app.core.config import settings
from app.models.user import User

logger = logging.getLogger(__name__)

TOOL_ROUNDS_EXHAUSTED = (
    "I hit the limit on data lookups for a single question before finishing. "
    "Try narrowing the question (a specific IP, user or shorter time range)."
)
REFUSAL_NOTICE = "I can't help with that request."


class AssistantUnavailableError(Exception):
    """No API key is configured, so the assistant is switched off."""


class AssistantUpstreamError(Exception):
    """The model API failed; `status_code` is what the router should return."""

    def __init__(self, message: str, status_code: int = 502) -> None:
        super().__init__(message)
        self.status_code = status_code


@dataclass
class ChatResult:
    reply: str
    model: str
    tools_used: list[dict[str, Any]] = field(default_factory=list)
    stop_reason: str | None = None


@lru_cache
def get_client() -> anthropic.Anthropic:
    """One shared client. Tests override the router dependency instead of this."""

    if not settings.anthropic_api_key:
        raise AssistantUnavailableError("ANTHROPIC_API_KEY is not configured.")
    return anthropic.Anthropic(api_key=settings.anthropic_api_key, timeout=60.0)


def _text(content: list[Any]) -> str:
    return "\n".join(block.text for block in content if block.type == "text" and block.text).strip()


def _execute_tool_calls(blocks: list[Any], ctx: ToolContext, tools_used: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Run every tool_use block; failures go back to the model as is_error results."""

    results: list[dict[str, Any]] = []
    for block in blocks:
        ok = True
        try:
            payload = json.dumps(run_tool(block.name, block.input, ctx), default=str)
        except ToolInputError as exc:
            ok, payload = False, str(exc)
        except SQLAlchemyError:
            logger.exception("Assistant tool %s failed", block.name)
            ctx.db.rollback()
            ok, payload = False, "The data could not be retrieved."
        tools_used.append({"name": block.name, "input": block.input, "ok": ok})
        results.append(
            {"type": "tool_result", "tool_use_id": block.id, "content": payload, **({} if ok else {"is_error": True})}
        )
    return results


def run_chat(
    client: anthropic.Anthropic,
    *,
    db: Session,
    user: User,
    messages: list[dict[str, str]],
    time_range_hours: int,
) -> ChatResult:
    """Answer one analyst turn, letting the model call read-only tools as needed."""

    now = utcnow()
    ctx = ToolContext(db=db, user=user, default_hours=time_range_hours, now=now)
    tool_defs = [tool.definition() for tool in tools_for(user)]
    system = build_system_prompt(
        now=now, time_range_hours=time_range_hours, role=user.role.name if user.role else "unknown"
    )

    conversation: list[dict[str, Any]] = list(messages)
    tools_used: list[dict[str, Any]] = []

    for _ in range(settings.assistant_max_tool_rounds + 1):
        try:
            response = client.messages.create(
                model=settings.assistant_model,
                max_tokens=settings.assistant_max_tokens,
                system=system,
                tools=tool_defs,
                messages=conversation,
            )
        except anthropic.RateLimitError as exc:
            raise AssistantUpstreamError("The AI service is rate limited. Try again shortly.", 429) from exc
        except anthropic.APIConnectionError as exc:
            raise AssistantUpstreamError("Could not reach the AI service.") from exc
        except anthropic.APIStatusError as exc:
            logger.error("Assistant model call failed: %s %s", exc.status_code, getattr(exc, "message", ""))
            raise AssistantUpstreamError("The AI service returned an error.") from exc

        if response.stop_reason == "refusal":
            return ChatResult(REFUSAL_NOTICE, settings.assistant_model, tools_used, response.stop_reason)

        if response.stop_reason != "tool_use":
            reply = _text(response.content)
            if response.stop_reason == "max_tokens":
                reply = f"{reply}\n\n[Response was cut off — ask me to continue or narrow the question.]".strip()
            return ChatResult(reply or "No response was generated.", settings.assistant_model, tools_used, response.stop_reason)

        # Echo the full assistant turn (including any thinking blocks) back
        # unchanged, then answer all tool calls together in one user message.
        conversation.append({"role": "assistant", "content": response.content})
        tool_blocks = [block for block in response.content if block.type == "tool_use"]
        conversation.append({"role": "user", "content": _execute_tool_calls(tool_blocks, ctx, tools_used)})

    return ChatResult(TOOL_ROUNDS_EXHAUSTED, settings.assistant_model, tools_used, "tool_rounds_exhausted")
