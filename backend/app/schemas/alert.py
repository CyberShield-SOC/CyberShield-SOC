from typing import Literal

from pydantic import BaseModel, model_validator


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
    severity: AlertSeverity | None = None
    status: AlertStatus | None = None

    @model_validator(mode="after")
    def require_update(self):
        if not self.model_fields_set:
            raise ValueError("Provide at least one alert field to update.")
        return self
