from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


AlertSeverity = Literal[
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
]

AlertStatus = Literal[
    "NEW",
    "REVIEWING",
    "ESCALATED",
    "CLOSED",
]


class AlertUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    severity: AlertSeverity | None = None
    status: AlertStatus | None = None
    expected_version: int | None = Field(None, gt=0)
    reason: str | None = Field(None, min_length=1, max_length=2000)

    @model_validator(mode="after")
    def require_update(self):
        if not any(field in self.model_fields_set and getattr(self, field) is not None for field in ("status", "severity")):
            raise ValueError("Provide at least one alert field to update.")
        return self
