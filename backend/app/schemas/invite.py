from datetime import datetime

from pydantic import BaseModel, Field, field_validator

from app.schemas.user import (
    SUPPORTED_ROLE_PATTERN,
    _normalize_email,
    _normalize_full_name,
    _normalize_username,
    _validate_password_policy,
)


class InviteCreateRequest(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    role: str = Field(pattern=SUPPORTED_ROLE_PATTERN)

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        return _normalize_email(value)


class InviteResponse(BaseModel):
    id: int
    email: str
    role: str
    invited_by: str | None = None
    created_at: datetime
    expires_at: datetime


class InviteListResponse(BaseModel):
    success: bool
    invites: list[InviteResponse]


class InviteCreateResponse(BaseModel):
    success: bool
    invite: InviteResponse


class InviteDetailsResponse(BaseModel):
    email: str
    role: str
    expires_at: datetime


class AcceptInviteRequest(BaseModel):
    token: str = Field(min_length=1, max_length=512)
    username: str = Field(min_length=3, max_length=50)
    full_name: str | None = Field(default=None, max_length=100)
    password: str = Field(min_length=1, max_length=256)

    @field_validator("username")
    @classmethod
    def normalize_username(cls, value: str) -> str:
        return _normalize_username(value)

    @field_validator("full_name")
    @classmethod
    def normalize_full_name(cls, value: str | None) -> str | None:
        return _normalize_full_name(value)

    @field_validator("password")
    @classmethod
    def enforce_password_policy(cls, value: str) -> str:
        return _validate_password_policy(value)


class AcceptInviteResponse(BaseModel):
    success: bool
    message: str
