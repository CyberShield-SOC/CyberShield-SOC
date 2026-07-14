from typing import Literal

from pydantic import BaseModel, Field


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
    "CLOSED",
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
    )

    priority: IncidentPriority | None = None


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
    )

    priority: IncidentPriority | None = None

    status: IncidentStatus | None = None