from pydantic import BaseModel, Field


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    email: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=8)
    role: str = Field(pattern="^(Admin|Analyst|Viewer)$")
    full_name: str | None = Field(default=None, max_length=100)


class UserRoleUpdate(BaseModel):
    role: str = Field(pattern="^(Admin|Analyst|Viewer)$")


class UserActiveUpdate(BaseModel):
    is_active: bool


class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    full_name: str | None = None
    is_active: bool
    role: str | None = None
