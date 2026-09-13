"""End-to-end coverage for the email-OTP two-factor login step.

The OTP is captured via a dependency override on the email sender (see
get_otp_email_sender) rather than a real Resend call, so these tests need no
network access or API key — and, since the override only ever sees the
plaintext code through this one seam, these tests double as proof the code
never appears in any HTTP response body.
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
from app.dispatch.otp_email import get_otp_email_sender
from app.main import app
from app.models.otp_verification import OtpVerification
from app.models.role import Role
from app.models.user import User
from app.security import hash_password


client = TestClient(app)


@pytest.fixture(autouse=True)
def clean_client():
    client.cookies.clear()
    yield
    client.cookies.clear()
    app.dependency_overrides.pop(get_otp_email_sender, None)


def csrf_headers() -> dict[str, str]:
    token = client.cookies.get(settings.auth_csrf_cookie_name)
    return {"X-CSRF-Token": token} if token else {}


def ensure_role(db: Session, name: str) -> Role:
    role = db.scalar(select(Role).where(Role.name == name))
    if role is None:
        role = Role(name=name, description=f"{name} test role")
        db.add(role)
        db.flush()
    return role


def create_user(db_session: Session, *, role_name: str = "Analyst") -> tuple[User, str]:
    role = ensure_role(db_session, role_name)
    suffix = uuid4().hex[:8]
    username = f"otp-{suffix}"
    password = "TwoFactorPassphrase-42!"
    user = User(
        username=username,
        email=f"{username}@example.test",
        password_hash=hash_password(password),
        role_id=role.id,
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    return user, password


def start_login(*, username: str, password: str, remember_me: bool = False):
    """POST /auth/login with the email sender overridden to capture the code.
    Returns (response, captured_code_or_None)."""

    captured: dict[str, str] = {}

    def fake_sender(*, to_email: str, code: str) -> None:
        captured["code"] = code
        captured["to_email"] = to_email

    app.dependency_overrides[get_otp_email_sender] = lambda: fake_sender
    response = client.post(
        "/auth/login",
        json={"username": username, "password": password, "remember_me": remember_me},
    )
    return response, captured.get("code"), captured.get("to_email")


def verify(code: str):
    return client.post("/auth/2fa/verify", json={"code": code}, headers=csrf_headers())


def resend():
    return client.post("/auth/2fa/resend", headers=csrf_headers())


# ── 1-2: correct password sends a 6-digit code, never in the response ──────

def test_correct_password_triggers_email_with_six_digit_code(db_session: Session):
    user, password = create_user(db_session)

    response, code, to_email = start_login(username=user.username, password=password)

    assert response.status_code == 200
    body = response.json()
    assert body == {"success": True, "requiresTwoFactor": True, "email": f"{user.username[:2]}***@example.test"}
    assert "access_token" not in body
    assert code is not None
    assert len(code) == 6
    assert code.isdigit()
    assert to_email == user.email
    # The pending-2FA cookie is set; the real session cookie is not.
    assert client.cookies.get(settings.otp_pending_cookie_name) is not None
    assert client.cookies.get(settings.auth_cookie_name) is None


def test_wrong_password_never_creates_a_pending_otp():
    response, code, _ = start_login(username="no-such-user", password="whatever-Passphrase-1!")
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid username or password"
    assert code is None
    assert client.cookies.get(settings.otp_pending_cookie_name) is None


# ── 3: correct OTP completes login and mints the real session ──────────────

def test_correct_otp_completes_login(db_session: Session):
    user, password = create_user(db_session)
    _, code, _ = start_login(username=user.username, password=password)

    result = verify(code)

    assert result.status_code == 200
    body = result.json()
    assert body["success"] is True
    assert body["user"]["username"] == user.username
    assert "access_token" in body and body["access_token"]
    assert client.cookies.get(settings.auth_cookie_name) is not None
    # The pending cookie is cleared once the real session exists.
    assert client.cookies.get(settings.otp_pending_cookie_name) is None

    me = client.get("/auth/me", headers={"Authorization": f"Bearer {body['access_token']}"})
    assert me.status_code == 200
    assert me.json()["user"]["username"] == user.username


# ── 4: incorrect OTP fails with a friendly message ──────────────────────────

def test_incorrect_otp_is_rejected_with_a_friendly_message(db_session: Session):
    user, password = create_user(db_session)
    _, code, _ = start_login(username=user.username, password=password)
    wrong_code = "000000" if code != "000000" else "111111"

    result = verify(wrong_code)

    assert result.status_code == 401
    assert result.json()["detail"] == "Invalid verification code. Please try again."
    # The correct code still works afterward (one wrong guess doesn't burn the code).
    assert verify(code).status_code == 200


# ── 5-6: expiry ──────────────────────────────────────────────────────────────

def test_expired_otp_cannot_complete_login(db_session: Session):
    user, password = create_user(db_session)
    _, code, _ = start_login(username=user.username, password=password)

    record = db_session.scalar(select(OtpVerification).where(OtpVerification.user_id == user.id))
    record.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    db_session.commit()

    result = verify(code)

    assert result.status_code == 401
    assert result.json()["detail"] == "Your verification code has expired. Request a new code."


# ── 7: a used OTP cannot be reused ──────────────────────────────────────────

def test_used_otp_cannot_be_reused(db_session: Session):
    user, password = create_user(db_session)
    _, code, _ = start_login(username=user.username, password=password)
    pending_cookie_value = client.cookies.get(settings.otp_pending_cookie_name)

    first = verify(code)
    assert first.status_code == 200

    # The server clears the pending cookie on success; re-inject the exact
    # same (cookie, code) pair to simulate a replay an attacker might have
    # captured beforehand. This proves the server-side used=True guard is
    # what stops reuse, not merely the client having lost the cookie.
    client.cookies.set(settings.otp_pending_cookie_name, pending_cookie_value)
    replay = verify(code)

    assert replay.status_code == 401
    # A used-up OTP and a not-found one share the same generic message —
    # deliberately, so a replay can't distinguish "already used" from
    # "never existed".
    assert replay.json()["detail"] == "Your verification code has expired. Request a new code."


# ── 8-9: resend issues a new code and invalidates the previous one ─────────

def test_resend_issues_a_new_code_and_invalidates_the_previous_one(db_session: Session, monkeypatch):
    user, password = create_user(db_session)
    _, first_code, _ = start_login(username=user.username, password=password)

    captured: dict[str, str] = {}

    def fake_sender(*, to_email: str, code: str) -> None:
        captured["code"] = code

    app.dependency_overrides[get_otp_email_sender] = lambda: fake_sender
    monkeypatch.setattr(settings, "otp_resend_cooldown_seconds", 0)

    resent = resend()
    assert resent.status_code == 200
    assert resent.json() == {"success": True, "message": "A new verification code has been sent."}
    second_code = captured["code"]
    assert second_code != first_code

    assert verify(first_code).status_code == 401
    assert verify(second_code).status_code == 200


def test_resend_is_blocked_immediately_after_login(db_session: Session):
    """The cooldown is timed from the original code's issuance too, not just
    between resends — otherwise a user could resend-spam right after their
    first login attempt."""

    user, password = create_user(db_session)
    start_login(username=user.username, password=password)

    app.dependency_overrides[get_otp_email_sender] = lambda: (lambda **_: None)
    immediate = resend()

    assert immediate.status_code == 429
    assert "wait" in immediate.json()["detail"].lower()


def test_resend_cooldown_rearms_after_each_resend(db_session: Session, monkeypatch):
    user, password = create_user(db_session)
    start_login(username=user.username, password=password)
    app.dependency_overrides[get_otp_email_sender] = lambda: (lambda **_: None)

    monkeypatch.setattr(settings, "otp_resend_cooldown_seconds", 0)
    first = resend()
    assert first.status_code == 200

    monkeypatch.setattr(settings, "otp_resend_cooldown_seconds", 60)
    second = resend()
    assert second.status_code == 429


# ── 11: five incorrect attempts lock the code out ───────────────────────────

def test_five_incorrect_attempts_lock_out_the_code(db_session: Session):
    user, password = create_user(db_session)
    _, code, _ = start_login(username=user.username, password=password)
    wrong_code = "000000" if code != "000000" else "111111"

    attempts = [verify(wrong_code) for _ in range(settings.otp_max_attempts)]
    for attempt in attempts[:-1]:
        assert attempt.status_code == 401
        assert attempt.json()["detail"] == "Invalid verification code. Please try again."
    # The attempt that crosses the limit locks the code out immediately.
    assert attempts[-1].status_code == 401
    assert attempts[-1].json()["detail"] == "Too many incorrect attempts. Request a new code."

    # Locked out means locked out — even the *correct* code no longer works;
    # the user must request a new one via resend.
    locked_out = verify(code)
    assert locked_out.status_code == 401


# ── 12: refreshing / no pending cookie never exposes anything ──────────────

def test_verify_without_a_pending_cookie_gives_a_generic_expired_message():
    response = client.post("/auth/2fa/verify", json={"code": "482913"})
    assert response.status_code == 401
    assert response.json()["detail"] == "Your verification code has expired. Request a new code."


def test_resend_without_a_pending_cookie_gives_a_generic_expired_message():
    response = client.post("/auth/2fa/resend")
    assert response.status_code == 401
    assert response.json()["detail"] == "Your verification code has expired. Request a new code."


# ── malformed input never leaks past the friendly message ──────────────────

def test_non_numeric_or_wrong_length_code_is_rejected_like_any_wrong_code(db_session: Session):
    user, password = create_user(db_session)
    start_login(username=user.username, password=password)

    for bad_code in ("abcdef", "12345", "1234567", ""):
        result = client.post("/auth/2fa/verify", json={"code": bad_code} if bad_code else {"code": " "}, headers=csrf_headers())
        assert result.status_code in (401, 422)
