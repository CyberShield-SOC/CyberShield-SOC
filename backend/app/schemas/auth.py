from pydantic import BaseModel, Field, field_validator

from app.schemas.user import UserResponse


class LoginRequest(BaseModel):
    username: str = Field(
        min_length=1,
        max_length=255,
        description="Account username or email address.",
    )
    password: str = Field(min_length=1, max_length=256)
    remember_me: bool = False

    @field_validator("username")
    @classmethod
    def normalize_username(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("Username or email is required.")
        return normalized


class LoginResponse(BaseModel):
    success: bool
    access_token: str
    token_type: str
    expires_in: int
    user: UserResponse


class RefreshResponse(BaseModel):
    success: bool
    access_token: str
    token_type: str
    expires_in: int
    user: UserResponse


class CurrentUserResponse(BaseModel):
    success: bool
    user: UserResponse
