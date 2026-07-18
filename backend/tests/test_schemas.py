import pytest
from pydantic import ValidationError

from app.schemas.auth import LoginRequest
from app.schemas.incident import IncidentCreate
from app.schemas.user import UserCreate, UserPasswordReset, UserUpdate


def test_login_normalizes_identifier_and_limits_password_size():
    payload = LoginRequest(username="  analyst@cybershield.io  ", password="valid")
    assert payload.username == "analyst@cybershield.io"

    with pytest.raises(ValidationError):
        LoginRequest(username="   ", password="valid")
    with pytest.raises(ValidationError):
        LoginRequest(username="analyst", password="x" * 257)


def test_user_creation_normalizes_identity_fields():
    payload = UserCreate(
        username="  analyst2  ",
        email="  Analyst2@Example.COM  ",
        password="StrongPassword123!",
        role="Analyst",
        full_name="  SOC Analyst  ",
    )
    assert payload.username == "analyst2"
    assert payload.email == "analyst2@example.com"
    assert payload.full_name == "SOC Analyst"


def test_user_update_requires_a_change_and_normalizes_identity_fields():
    payload = UserUpdate(
        username="  viewer2  ",
        email=" Viewer2@Example.COM ",
        full_name="  Workspace Viewer  ",
        role="Viewer",
        is_active=False,
    )
    assert payload.username == "viewer2"
    assert payload.email == "viewer2@example.com"
    assert payload.full_name == "Workspace Viewer"

    with pytest.raises(ValidationError):
        UserUpdate()
    with pytest.raises(ValidationError):
        UserUpdate(email=None)


def test_admin_password_reset_enforces_the_shared_password_bounds():
    assert UserPasswordReset(new_password="StrongPassword123!").new_password == "StrongPassword123!"
    with pytest.raises(ValidationError):
        UserPasswordReset(new_password="too-short")


@pytest.mark.parametrize("email", ["missing-at.example.com", "a@localhost", "a@.example.com"])
def test_user_creation_rejects_malformed_email(email):
    with pytest.raises(ValidationError):
        UserCreate(
            username="analyst2",
            email=email,
            password="StrongPassword123!",
            role="Analyst",
        )


def test_incident_text_is_trimmed_and_blank_text_is_rejected():
    payload = IncidentCreate(alert_id=1, title="  Investigation  ", description="  Evidence summary  ")
    assert payload.title == "Investigation"
    assert payload.description == "Evidence summary"

    with pytest.raises(ValidationError):
        IncidentCreate(alert_id=1, title="   ")
