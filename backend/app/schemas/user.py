from pydantic import BaseModel, Field, field_validator, model_validator


SUPPORTED_ROLE_PATTERN = "^(Admin|Analyst|Viewer)$"


def _normalize_username(value: str) -> str:
    normalized = value.strip()
    if len(normalized) < 3:
        raise ValueError("Username must contain at least 3 non-space characters.")
    return normalized


def _normalize_email(value: str) -> str:
    normalized = value.strip().lower()
    local, separator, domain = normalized.partition("@")
    if not separator or not local or "." not in domain or domain.startswith(".") or domain.endswith("."):
        raise ValueError("Enter a valid email address.")
    return normalized


def _normalize_full_name(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip()
    return normalized or None


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    email: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=12, max_length=256)
    role: str = Field(pattern=SUPPORTED_ROLE_PATTERN)
    full_name: str | None = Field(default=None, max_length=100)

    @field_validator("username")
    @classmethod
    def normalize_username(cls, value: str) -> str:
        return _normalize_username(value)

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        return _normalize_email(value)

    @field_validator("full_name")
    @classmethod
    def normalize_full_name(cls, value: str | None) -> str | None:
        return _normalize_full_name(value)


class UserUpdate(BaseModel):
    """Admin-editable account fields; password changes use a separate endpoint."""

    username: str | None = Field(default=None, min_length=3, max_length=50)
    email: str | None = Field(default=None, min_length=3, max_length=255)
    full_name: str | None = Field(default=None, max_length=100)
    role: str | None = Field(default=None, pattern=SUPPORTED_ROLE_PATTERN)
    is_active: bool | None = None

    @field_validator("username")
    @classmethod
    def normalize_username(cls, value: str | None) -> str | None:
        return _normalize_username(value) if value is not None else None

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str | None) -> str | None:
        return _normalize_email(value) if value is not None else None

    @field_validator("full_name")
    @classmethod
    def normalize_full_name(cls, value: str | None) -> str | None:
        return _normalize_full_name(value)

    @model_validator(mode="after")
    def require_change(self):
        if not self.model_fields_set:
            raise ValueError("Provide at least one user field to update.")
        for field_name in ("username", "email", "role", "is_active"):
            if field_name in self.model_fields_set and getattr(self, field_name) is None:
                raise ValueError(f"{field_name} cannot be null.")
        return self


class UserPasswordReset(BaseModel):
    """A write-only replacement password. It is never serialized back to clients."""

    new_password: str = Field(min_length=12, max_length=256)


class UserRoleUpdate(BaseModel):
    role: str = Field(pattern=SUPPORTED_ROLE_PATTERN)


class UserActiveUpdate(BaseModel):
    is_active: bool


class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    full_name: str | None = None
    is_active: bool
    role: str | None = None
