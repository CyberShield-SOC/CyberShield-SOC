from __future__ import annotations

from pydantic import BaseModel, Field, field_validator


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
    cooldown_seconds: int | None = Field(default=None, ge=0, le=86_400)
    confidence: int | None = Field(default=None, ge=0, le=100)
    allowlist: list[str] | None = None
    start_hour: int | None = Field(default=None, ge=0, le=23)
    end_hour: int | None = Field(default=None, ge=0, le=23)
    params: dict[str, bool | int | float | str] | None = None

    @field_validator("allowlist")
    @classmethod
    def clean_allowlist(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return None
        cleaned = [item.strip() for item in value if item and item.strip()]
        if len(cleaned) > 500 or any(len(item) > 255 for item in cleaned):
            raise ValueError("Allowlists hold at most 500 entries of 255 characters each.")
        return list(dict.fromkeys(cleaned))
