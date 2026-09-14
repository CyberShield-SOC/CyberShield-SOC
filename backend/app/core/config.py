from functools import lru_cache
from pathlib import Path
from typing import Any

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


# Repository root:
# CyberShield-SOC/backend/app/core/config.py
# parents[3] points to CyberShield-SOC/
PROJECT_ROOT = Path(__file__).resolve().parents[3]
ENV_FILE = PROJECT_ROOT / ".env"


class Settings(BaseSettings):
    """Application configuration loaded from environment variables."""

    database_url: str
    auth_session_ttl_minutes: int = Field(default=60, ge=5, le=1440)
    auth_remember_ttl_days: int = Field(default=7, ge=1, le=90)
    auth_cookie_name: str = Field(default="cybershield_session", min_length=1, max_length=100)
    auth_csrf_cookie_name: str = Field(default="cybershield_csrf", min_length=1, max_length=100)
    auth_cookie_secure: bool = False
    jwt_secret_key: str
    jwt_algorithm: str = Field(default="HS256", min_length=1, max_length=20)
    jwt_access_ttl_minutes: int = Field(default=10, ge=1, le=60)
    password_min_length: int = Field(default=12, ge=8, le=128)
    email_verify_deliverability: bool = False
    slack_webhook_url: str | None = None
    detection_rule_config: dict[str, Any] = Field(default_factory=dict)
    # Comma-separated extra browser origins allowed to call the API — added
    # to the built-in localhost dev origins, never replacing them. Needed
    # only when the frontend is deployed on a different origin than the API
    # (e.g. Railway services deployed separately); a combined deployment
    # that serves the built frontend from this same FastAPI app needs none.
    cors_allowed_origins: str = ""

    # Email one-time-passcode two-factor step (see app/routers/auth.py).
    resend_api_key: str | None = None
    resend_from_email: str = Field(default="CyberShield <onboarding@resend.dev>", min_length=3)
    otp_secret: str = Field(min_length=16)
    otp_expiry_minutes: int = Field(default=5, ge=1, le=30)
    otp_max_attempts: int = Field(default=5, ge=1, le=10)
    otp_resend_cooldown_seconds: int = Field(default=60, ge=10, le=600)
    otp_pending_cookie_name: str = Field(default="cybershield_2fa_pending", min_length=1, max_length=100)

    # Optional local MaxMind-format databases for geo identity rules
    # (impossible_travel, first_seen_geo_asn). See app/detection/geoip.py.
    geoip_city_db_path: str | None = None
    geoip_asn_db_path: str | None = None

    # Forgot-password email flow (see app/routers/auth.py).
    reset_token_expiry_minutes: int = Field(default=30, ge=5, le=1440)
    # Base URL of the deployed frontend, used to build the link emailed to
    # /auth/forgot-password requesters. No trailing slash. Defaults to the
    # Vite dev server's own HTTPS origin (see frontend/vite.config.js).
    frontend_base_url: str = Field(default="https://127.0.0.1:5173", min_length=1)

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
