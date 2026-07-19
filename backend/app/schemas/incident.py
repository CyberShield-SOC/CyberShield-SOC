from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator


IncidentPriority = Literal[
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
]

IncidentStatus = Literal[
    "OPEN",
    "INVESTIGATING",
    "RESOLVED",
    "FALSE_POSITIVE",
]


class IncidentCreate(BaseModel):
    """Request body for creating an incident from an alert."""

    alert_id: int = Field(
        gt=0,
        description="Persistent alert ID used to create the incident.",
    )

    assigned_user_id: int | None = Field(
        default=None,
        gt=0,
    )

    title: str | None = Field(
        default=None,
        min_length=1,
        max_length=150,
    )

    description: str | None = Field(
        default=None,
        min_length=1,
        max_length=5000,
    )

    priority: IncidentPriority | None = None

    @field_validator("title", "description")
    @classmethod
    def normalize_optional_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            raise ValueError("Incident text cannot be blank.")
        return normalized


class IncidentUpdate(BaseModel):
    """Fields that may be changed during an investigation."""

    assigned_user_id: int | None = Field(
        default=None,
        gt=0,
    )

    title: str | None = Field(
        default=None,
        min_length=1,
        max_length=150,
    )

    description: str | None = Field(
        default=None,
        min_length=1,
        max_length=5000,
    )

    priority: IncidentPriority | None = None

    status: IncidentStatus | None = None

    @field_validator("title", "description")
    @classmethod
    def normalize_optional_text(cls, value: str | None) -> str | None:
        return IncidentCreate.normalize_optional_text(value)

    @model_validator(mode="after")
    def require_update(self):
        if not self.model_fields_set:
            raise ValueError("Provide at least one incident field to update.")
        return self
