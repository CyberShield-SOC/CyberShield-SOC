from typing import Literal

from pydantic import BaseModel


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
