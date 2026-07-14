from pydantic import BaseModel, Field, field_validator


class NoteCreate(BaseModel):
    """Request body for adding a note to an incident."""

    author_user_id: int = Field(
        gt=0,
        description="User ID of the analyst writing the note.",
    )

    body: str = Field(
        min_length=1,
        max_length=5000,
        description="Analyst investigation note.",
    )

    @field_validator("body")
    @classmethod
    def body_must_not_be_blank(cls, value: str) -> str:
        cleaned = value.strip()

        if not cleaned:
            raise ValueError("Note body cannot be blank.")

        return cleaned