from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


# Repository root:
# CyberShield-SOC/backend/app/core/config.py
# parents[3] points to CyberShield-SOC/
PROJECT_ROOT = Path(__file__).resolve().parents[3]
ENV_FILE = PROJECT_ROOT / ".env"


class Settings(BaseSettings):
    """Application configuration loaded from environment variables."""

    database_url: str
    auth_session_ttl_minutes: int = 60

    model_config = SettingsConfigDict(
        env_file=ENV_FILE,
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    """Return one cached settings object for the application."""

    return Settings()


settings = get_settings()
