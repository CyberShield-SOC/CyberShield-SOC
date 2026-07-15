from pydantic import BaseModel, Field

from app.schemas.user import UserResponse


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=50)
    password: str = Field(min_length=1)


class LoginResponse(BaseModel):
    success: bool
    access_token: str
    token_type: str
    user: UserResponse


class CurrentUserResponse(BaseModel):
    success: bool
    user: UserResponse
