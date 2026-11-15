"""End-to-end coverage for the invite-based signup flow:

Admin (POST /users/invites) -> invitee (GET /auth/invite/{token},
POST /auth/accept-invite) -> Admin pending-invite management
(GET/resend/revoke /users/invites).

The invite link is captured via a dependency override on the email sender
(see get_invite_email_sender) rather than a real Resend call, so these tests
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

from app.dispatch.invite_email import get_invite_email_sender
from app.main import app
from app.models.invite_token import InviteToken
from app.models.role import Role
from app.models.user import User
from app.security import current_user, hash_password, verify_password


client = TestClient(app)


@pytest.fixture(autouse=True)
def clean_client():
    client.cookies.clear()
    yield
    client.cookies.clear()
    app.dependency_overrides.pop(get_invite_email_sender, None)
    app.dependency_overrides.pop(current_user, None)


def ensure_role(db: Session, name: str) -> Role:
    role = db.scalar(select(Role).where(Role.name == name))
    if role is None:
        role = Role(name=name, description=f"{name} test role")
        db.add(role)
        db.flush()
    return role


def create_persisted_user(db_session: Session, *, role_name: str) -> User:
    """A real, committed account the request handler (a different session on
    the same connection) can see — unlike an in-memory fake, this satisfies
    the invite_tokens.invited_by_user_id foreign key."""

    role = ensure_role(db_session, role_name)
    suffix = uuid4().hex[:8]
    username = f"{role_name.lower()}-{suffix}"
    user = User(
        username=username,
        email=f"{username}@example.test",
        password_hash=hash_password("Irrelevant-Passphrase-1!"),
        role_id=role.id,
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    user.role = role
    return user


def as_user(user: User) -> None:
    app.dependency_overrides[current_user] = lambda: user


def send_invite(email: str, role: str):
    """POST /users/invites with the email sender overridden to capture the
    invite link's token. Returns (response, token_or_None, to_email_or_None)."""

    captured: dict[str, str] = {}

    def fake_sender(*, to_email: str, invite_link: str, role: str) -> None:
        captured["to_email"] = to_email
        captured["role"] = role
        captured["token"] = invite_link.rsplit("token=", 1)[-1]

    app.dependency_overrides[get_invite_email_sender] = lambda: fake_sender
    response = client.post("/users/invites", json={"email": email, "role": role})
    return response, captured.get("token"), captured.get("to_email")


def resend(invite_id: int):
    captured: dict[str, str] = {}

    def fake_sender(*, to_email: str, invite_link: str, role: str) -> None:
        captured["token"] = invite_link.rsplit("token=", 1)[-1]

    app.dependency_overrides[get_invite_email_sender] = lambda: fake_sender
    response = client.post(f"/users/invites/{invite_id}/resend")
    return response, captured.get("token")


def accept_invite(token: str, *, username: str, password: str, full_name: str | None = "New Analyst"):
    return client.post(
        "/auth/accept-invite",
        json={
            "token": token,
            "username": username,
            "full_name": full_name,
            "password": password,
        },
    )


# ── creating an invite (Admin-only) ─────────────────────────────────────────

def test_non_admin_cannot_create_invite(db_session: Session):
    analyst = create_persisted_user(db_session, role_name="Analyst")
    as_user(analyst)

    response = client.post("/users/invites", json={"email": "new@example.test", "role": "Analyst"})

    assert response.status_code == 403


def test_admin_can_create_invite(db_session: Session):
    admin = create_persisted_user(db_session, role_name="Admin")
    as_user(admin)

    response, token, to_email = send_invite("new-analyst@example.test", "Analyst")

    assert response.status_code == 201
    body = response.json()
    assert body["success"] is True
    assert body["invite"]["email"] == "new-analyst@example.test"
    assert body["invite"]["role"] == "Analyst"
    assert token is not None
    assert to_email == "new-analyst@example.test"
    # The token itself is never part of the response body.
    assert token not in response.text


def test_invite_email_send_failure_returns_502_and_persists_nothing(db_session: Session):
    admin = create_persisted_user(db_session, role_name="Admin")
    as_user(admin)

    def failing_sender(*, to_email: str, invite_link: str, role: str) -> None:
        raise RuntimeError("Resend is down")

    app.dependency_overrides[get_invite_email_sender] = lambda: failing_sender
    response = client.post("/users/invites", json={"email": "ghost@example.test", "role": "Analyst"})

    assert response.status_code == 502
    remaining = db_session.scalar(select(InviteToken).where(InviteToken.email == "ghost@example.test"))
    assert remaining is None


# ── viewing invite details (public, pre-accept) ─────────────────────────────

def test_invite_details_returns_email_and_role_without_consuming(db_session: Session):
    admin = create_persisted_user(db_session, role_name="Admin")
    as_user(admin)
    _, token, _ = send_invite("viewer-to-be@example.test", "Viewer")

    first = client.get(f"/auth/invite/{token}")
    second = client.get(f"/auth/invite/{token}")

    assert first.status_code == 200
    assert first.json() == {
        "email": "viewer-to-be@example.test",
        "role": "Viewer",
        "expires_at": first.json()["expires_at"],
    }
    # Viewing details doesn't consume the token.
    assert second.status_code == 200


def test_unknown_invite_token_is_rejected():
    response = client.get("/auth/invite/not-a-real-token")
    assert response.status_code == 400


# ── accepting an invite ──────────────────────────────────────────────────────

def test_accepting_an_invite_creates_an_active_account_with_the_invited_role(db_session: Session):
    admin = create_persisted_user(db_session, role_name="Admin")
    as_user(admin)
    _, token, _ = send_invite("new-analyst-2@example.test", "Analyst")

    result = accept_invite(token, username=f"newanalyst{uuid4().hex[:6]}", password="BrandNewPassphrase-77!")

    assert result.status_code == 200
    assert result.json()["success"] is True

    created = db_session.scalar(select(User).where(User.email == "new-analyst-2@example.test"))
    assert created is not None
    assert created.is_active is True
    assert created.role.name == "Analyst"
    assert verify_password("BrandNewPassphrase-77!", created.password_hash)


def test_invite_token_cannot_be_reused(db_session: Session):
    admin = create_persisted_user(db_session, role_name="Admin")
    as_user(admin)
    _, token, _ = send_invite("single-use@example.test", "Viewer")

    username = f"singleuse{uuid4().hex[:6]}"
    first = accept_invite(token, username=username, password="BrandNewPassphrase-77!")
    assert first.status_code == 200

    replay = accept_invite(token, username=f"replay{uuid4().hex[:6]}", password="AnotherPassphrase-88!")
    assert replay.status_code == 400
    assert "invalid" in replay.json()["detail"].lower()


def test_expired_invite_is_rejected(db_session: Session):
    admin = create_persisted_user(db_session, role_name="Admin")
    as_user(admin)
    _, token, _ = send_invite("expired@example.test", "Viewer")

    record = db_session.scalar(select(InviteToken).where(InviteToken.email == "expired@example.test"))
    record.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    db_session.commit()

    result = accept_invite(token, username=f"toolate{uuid4().hex[:6]}", password="BrandNewPassphrase-77!")
    assert result.status_code == 400
    assert "expired" in result.json()["detail"].lower()


def test_revoked_invite_is_rejected(db_session: Session):
    admin = create_persisted_user(db_session, role_name="Admin")
    as_user(admin)
    response, token, _ = send_invite("revoked@example.test", "Viewer")
    invite_id = response.json()["invite"]["id"]

    assert client.delete(f"/users/invites/{invite_id}").status_code == 200

    details = client.get(f"/auth/invite/{token}")
    accept = accept_invite(token, username=f"revoked{uuid4().hex[:6]}", password="BrandNewPassphrase-77!")

    assert details.status_code == 400
    assert accept.status_code == 400


def test_password_failing_the_shared_policy_does_not_burn_the_token(db_session: Session):
    admin = create_persisted_user(db_session, role_name="Admin")
    as_user(admin)
    _, token, _ = send_invite("policy-check@example.test", "Viewer")
    username = f"policycheck{uuid4().hex[:6]}"

    weak = accept_invite(token, username=username, password="short")
    assert weak.status_code == 422

    strong = accept_invite(token, username=username, password="BrandNewPassphrase-77!")
    assert strong.status_code == 200


def test_duplicate_username_on_accept_is_rejected(db_session: Session):
    admin = create_persisted_user(db_session, role_name="Admin")
    as_user(admin)
    existing = create_persisted_user(db_session, role_name="Viewer")

    _, token, _ = send_invite("username-clash@example.test", "Viewer")

    result = accept_invite(token, username=existing.username, password="BrandNewPassphrase-77!")
    assert result.status_code == 409


# ── inviting the same email twice supersedes the earlier token ─────────────

def test_reinviting_the_same_email_invalidates_the_previous_token(db_session: Session):
    admin = create_persisted_user(db_session, role_name="Admin")
    as_user(admin)

    _, first_token, _ = send_invite("twice-invited@example.test", "Viewer")
    _, second_token, _ = send_invite("twice-invited@example.test", "Analyst")

    assert first_token != second_token
    stale = accept_invite(first_token, username=f"stale{uuid4().hex[:6]}", password="BrandNewPassphrase-77!")
    fresh = accept_invite(second_token, username=f"fresh{uuid4().hex[:6]}", password="BrandNewPassphrase-77!")

    assert stale.status_code == 400
    assert fresh.status_code == 200

    created = db_session.scalar(select(User).where(User.email == "twice-invited@example.test"))
    assert created.role.name == "Analyst"


# ── Admin pending-invite management ─────────────────────────────────────────

def test_list_pending_invites_is_admin_only_and_excludes_accepted_invites(db_session: Session):
    admin = create_persisted_user(db_session, role_name="Admin")
    as_user(admin)
    _, pending_token, _ = send_invite("still-pending@example.test", "Viewer")
    _, accepted_token, _ = send_invite("will-accept@example.test", "Viewer")
    accept_invite(accepted_token, username=f"accepted{uuid4().hex[:6]}", password="BrandNewPassphrase-77!")

    listed = client.get("/users/invites")

    assert listed.status_code == 200
    emails = {invite["email"] for invite in listed.json()["invites"]}
    assert "still-pending@example.test" in emails
    assert "will-accept@example.test" not in emails

    analyst = create_persisted_user(db_session, role_name="Analyst")
    as_user(analyst)
    assert client.get("/users/invites").status_code == 403


def test_resend_invite_issues_a_new_token_and_retires_the_old_one(db_session: Session):
    admin = create_persisted_user(db_session, role_name="Admin")
    as_user(admin)
    response, original_token, _ = send_invite("resend-me@example.test", "Viewer")
    invite_id = response.json()["invite"]["id"]

    resend_response, new_token = resend(invite_id)

    assert resend_response.status_code == 200
    assert new_token != original_token

    stale = accept_invite(original_token, username=f"staleresend{uuid4().hex[:6]}", password="BrandNewPassphrase-77!")
    fresh = accept_invite(new_token, username=f"freshresend{uuid4().hex[:6]}", password="BrandNewPassphrase-77!")

    assert stale.status_code == 400
    assert fresh.status_code == 200


def test_revoke_invite_removes_it_from_the_pending_list(db_session: Session):
    admin = create_persisted_user(db_session, role_name="Admin")
    as_user(admin)
    response, _, _ = send_invite("to-be-revoked@example.test", "Viewer")
    invite_id = response.json()["invite"]["id"]

    revoke = client.delete(f"/users/invites/{invite_id}")
    listed = client.get("/users/invites")

    assert revoke.status_code == 200
    assert all(invite["email"] != "to-be-revoked@example.test" for invite in listed.json()["invites"])


def test_revoking_an_unknown_invite_is_a_404(db_session: Session):
    admin = create_persisted_user(db_session, role_name="Admin")
    as_user(admin)

    assert client.delete("/users/invites/999999999").status_code == 404
