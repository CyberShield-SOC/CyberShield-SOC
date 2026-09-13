from __future__ import annotations

from pydantic import BaseModel, Field


class DetectionRuleUpdate(BaseModel):
    """Partial update for a built-in rule's enabled state and thresholds.

    Every field is optional so a caller can flip `enabled` without resending
    thresholds it isn't changing. Only fields present in the request body are
    applied — see `.model_dump(exclude_unset=True)` in the router.
    """

    enabled: bool | None = None
    threshold: int | None = Field(default=None, ge=1, le=10_000)
    fail_threshold: int | None = Field(default=None, ge=1, le=10_000)
    window_seconds: int | None = Field(default=None, ge=1, le=86_400)
    success_window_seconds: int | None = Field(default=None, ge=1, le=86_400)
