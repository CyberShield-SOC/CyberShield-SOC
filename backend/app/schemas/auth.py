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


class TwoFactorRequiredResponse(BaseModel):
    """Returned by /auth/login in place of tokens until the OTP is verified."""

    success: bool
    requiresTwoFactor: bool = True
    email: str


class TwoFactorVerifyRequest(BaseModel):
    # Deliberately not constrained to \d{6} here: a malformed code should
    # fail with the same friendly "Invalid verification code" message as a
    # wrong-but-well-formed one, not a generic schema-validation error.
    code: str = Field(min_length=1, max_length=32)


class TwoFactorResendResponse(BaseModel):
    success: bool
    message: str


class RefreshResponse(BaseModel):
    success: bool
    access_token: str
    token_type: str
    expires_in: int
    user: UserResponse


class CurrentUserResponse(BaseModel):
    success: bool
    user: UserResponse
