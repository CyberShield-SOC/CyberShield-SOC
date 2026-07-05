from __future__ import annotations

from typing import Optional

from pydantic import BaseModel


class LogRecord(BaseModel):
    """Normalised view of a single parsed log line consumed by the detection engine."""

    line_number: int
    timestamp: Optional[str] = None
    ip_address: Optional[str] = None
    username: Optional[str] = None
    event_type: Optional[str] = None
    status: Optional[str] = None


class Alert(BaseModel):
    """Detection result emitted by any rule — shared contract for the React dashboard."""

    rule: str
    severity: str                        # "HIGH" | "MEDIUM" | "LOW"
    source_ip: Optional[str] = None
    username: Optional[str] = None
    count: int
    time_window_seconds: int
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    description: str
    matched_line_numbers: list[int]
