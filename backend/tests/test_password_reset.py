"""End-to-end coverage for the /auth/forgot-password + /auth/reset-password flow.

The reset link is captured via a dependency override on the email sender
(see get_reset_email_sender) rather than a real Resend call, so these tests
need no network access or API key — and, since the override only ever sees
the plaintext token through this one seam, these tests double as proof the
token never appears in any HTTP response body.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.config import settings
from app.dispatch.reset_email import get_reset_email_sender
from app.main import app
from app.models.auth_session import AuthSession
from app.models.password_reset_token import PasswordResetToken
from app.models.role import Role
from app.models.user import User
from app.security import hash_password, verify_password


client = TestClient(app)


@pytest.fixture(autouse=True)
def clean_client():
    client.cookies.clear()
    yield
    client.cookies.clear()
    app.dependency_overrides.pop(get_reset_email_sender, None)


def ensure_role(db: Session, name: str) -> Role:
    role = db.scalar(select(Role).where(Role.name == name))
    if role is None:
        role = Role(name=name, description=f"{name} test role")
        db.add(role)
        db.flush()
    return role


def create_user(db_session: Session, *, role_name: str = "Analyst", is_active: bool = True) -> tuple[User, str]:
    role = ensure_role(db_session, role_name)
    suffix = uuid4().hex[:8]
    username = f"reset-{suffix}"
    password = "OriginalPassphrase-42!"
    user = User(
        username=username,
        email=f"{username}@example.test",
        password_hash=hash_password(password),
        role_id=role.id,
        is_active=is_active,
    )
    db_session.add(user)
    db_session.commit()
    return user, password


def request_reset(email: str):
    """POST /auth/forgot-password with the email sender overridden to
    capture the token. Returns (response, captured_token_or_None, captured_to_email)."""

    captured: dict[str, str] = {}

    def fake_sender(*, to_email: str, reset_link: str) -> None:
        captured["to_email"] = to_email
        captured["token"] = reset_link.rsplit("token=", 1)[-1]

    app.dependency_overrides[get_reset_email_sender] = lambda: fake_sender
    response = client.post("/auth/forgot-password", json={"email": email})
    return response, captured.get("token"), captured.get("to_email")


def do_reset(token: str, new_password: str):
    return client.post(
        "/auth/reset-password",
        json={"token": token, "new_password": new_password},
    )


# ── the response never reveals whether the account exists ──────────────────

def test_known_and_unknown_email_get_the_identical_response(db_session: Session):
    user, _ = create_user(db_session)

    known, known_token, known_to = request_reset(user.email)
    unknown, unknown_token, unknown_to = request_reset("no-such-account@example.test")

    assert known.status_code == 200
    assert unknown.status_code == 200
    assert known.json() == unknown.json()
    assert known_token is not None and known_to == user.email
    assert unknown_token is None and unknown_to is None


def test_email_match_is_case_insensitive(db_session: Session):
    user, _ = create_user(db_session)

    response, token, to_email = request_reset(user.email.upper())

    assert response.status_code == 200
    assert token is not None
    assert to_email == user.email


def test_inactive_account_gets_the_generic_response_but_no_email(db_session: Session):
    user, _ = create_user(db_session, is_active=False)

    response, token, to_email = request_reset(user.email)

    assert response.status_code == 200
    assert token is None
    assert to_email is None


# ── completing a reset ──────────────────────────────────────────────────────

def test_valid_token_resets_the_password_and_logs_in_with_it(db_session: Session):
    user, old_password = create_user(db_session)
    _, token, _ = request_reset(user.email)

    result = do_reset(token, "BrandNewPassphrase-77!")

    assert result.status_code == 200
    assert result.json()["success"] is True

    db_session.refresh(user)
    assert verify_password("BrandNewPassphrase-77!", user.password_hash)
    assert not verify_password(old_password, user.password_hash)


def test_reset_revokes_every_existing_session(db_session: Session):
    user, _ = create_user(db_session)
    db_session.add(
        AuthSession(
            user_id=user.id,
            token_hash="a" * 64,
            expires_at=datetime.now(timezone.utc) + timedelta(days=1),
        )
    )
    db_session.commit()

    _, token, _ = request_reset(user.email)
    assert do_reset(token, "BrandNewPassphrase-77!").status_code == 200

    session = db_session.scalar(select(AuthSession).where(AuthSession.user_id == user.id))
    assert session.revoked_at is not None


def test_token_cannot_be_reused(db_session: Session):
    user, _ = create_user(db_session)
    _, token, _ = request_reset(user.email)

    first = do_reset(token, "BrandNewPassphrase-77!")
    assert first.status_code == 200

    replay = do_reset(token, "AnotherPassphrase-88!")
    assert replay.status_code == 400
    assert "invalid" in replay.json()["detail"].lower()


def test_unknown_token_is_rejected(db_session: Session):
    result = do_reset("not-a-real-token", "BrandNewPassphrase-77!")
    assert result.status_code == 400


def test_expired_token_is_rejected(db_session: Session):
    user, _ = create_user(db_session)
    _, token, _ = request_reset(user.email)

    record = db_session.scalar(select(PasswordResetToken).where(PasswordResetToken.user_id == user.id))
    record.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    db_session.commit()

    result = do_reset(token, "BrandNewPassphrase-77!")
    assert result.status_code == 400
    assert "expired" in result.json()["detail"].lower()


def test_requesting_a_new_reset_invalidates_the_previous_token(db_session: Session):
    user, _ = create_user(db_session)
    _, first_token, _ = request_reset(user.email)
    _, second_token, _ = request_reset(user.email)

    assert first_token != second_token
    assert do_reset(first_token, "BrandNewPassphrase-77!").status_code == 400
    assert do_reset(second_token, "BrandNewPassphrase-77!").status_code == 200


def test_password_failing_the_shared_policy_is_rejected(db_session: Session):
    user, _ = create_user(db_session)
    _, token, _ = request_reset(user.email)

    result = do_reset(token, "short")
    assert result.status_code == 422


def test_password_containing_the_username_is_rejected(db_session: Session):
    user, _ = create_user(db_session)
    _, token, _ = request_reset(user.email)

    result = do_reset(token, f"{user.username}Passphrase-1!")
    assert result.status_code == 422
    # The token isn't burned by a policy rejection, so a compliant password
    # can still be submitted with the same link.
    assert do_reset(token, "BrandNewPassphrase-77!").status_code == 200


def test_email_send_failure_still_returns_the_generic_success_response(db_session: Session):
    user, _ = create_user(db_session)

    def failing_sender(*, to_email: str, reset_link: str) -> None:
        raise RuntimeError("Resend is down")

    app.dependency_overrides[get_reset_email_sender] = lambda: failing_sender
    response = client.post("/auth/forgot-password", json={"email": user.email})

    assert response.status_code == 200
    assert response.json()["success"] is True
    # No usable token exists server-side either, since the challenge was
    # rolled back along with the failed send.
    assert (
        db_session.scalar(
            select(PasswordResetToken).where(PasswordResetToken.user_id == user.id)
        )
        is None
    )
