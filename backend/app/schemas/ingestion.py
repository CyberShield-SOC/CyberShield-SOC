"""Collector request contract. Content uses the same parsers as file uploads."""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class IngestionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_name: str = Field(min_length=1, max_length=255)
    source_type: Literal["syslog", "file", "agent", "api"] = "api"
    source_host: str | None = Field(default=None, min_length=1, max_length=255)
    filename: str = Field(default="events.jsonl", min_length=1, max_length=255)
    content: str = Field(min_length=1, max_length=10 * 1024 * 1024)

    @field_validator("source_name", "source_host")
    @classmethod
    def clean_identity(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if not value or any(ord(char) < 32 for char in value):
            raise ValueError("Source identity must contain printable, nonblank text.")
        return value
