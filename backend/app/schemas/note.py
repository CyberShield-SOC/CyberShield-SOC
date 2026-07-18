from pydantic import BaseModel, Field, field_validator, model_validator


class NoteCreate(BaseModel):
    """Request body for adding a note to an incident."""

    title: str = Field(default="Analyst note", min_length=1, max_length=100)
    body: str = Field(
        min_length=1,
        max_length=5000,
        description="Analyst investigation note.",
    )
    tags: list[str] = Field(default_factory=list, max_length=6)

    @field_validator("body")
    @classmethod
    def body_must_not_be_blank(cls, value: str) -> str:
        cleaned = value.strip()

        if not cleaned:
            raise ValueError("Note body cannot be blank.")

        return cleaned

    @field_validator("title")
    @classmethod
    def title_must_not_be_blank(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("Note title cannot be blank.")
        return cleaned

    @field_validator("tags")
    @classmethod
    def normalize_tags(cls, values: list[str]) -> list[str]:
        cleaned = []
        for value in values:
            tag = value.strip().lower()
            if not tag or tag in cleaned:
                continue
            if len(tag) > 40:
                raise ValueError("Note tags cannot exceed 40 characters.")
            cleaned.append(tag)
        return cleaned


class NoteUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=100)
    body: str | None = Field(default=None, min_length=1, max_length=5000)
    tags: list[str] | None = Field(default=None, max_length=6)
    pinned: bool | None = None
    archived: bool | None = None

    @field_validator("title", "body")
    @classmethod
    def text_must_not_be_blank(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("Note text cannot be blank.")
        return cleaned

    @field_validator("tags")
    @classmethod
    def normalize_optional_tags(cls, values: list[str] | None) -> list[str] | None:
        return NoteCreate.normalize_tags(values) if values is not None else None

    @model_validator(mode="after")
    def require_update(self):
        if not self.model_fields_set:
            raise ValueError("Provide at least one note field to update.")
        return self
