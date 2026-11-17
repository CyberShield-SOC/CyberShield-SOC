"""Authenticator-app MFA: RFC vectors, enrolment, sign-in, recovery, removal."""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.dispatch.otp_email import get_otp_email_sender
from app.main import app
from app.models.audit_event import AuditEvent
from app.models.mfa_recovery_code import MfaRecoveryCode
from app.models.role import Role
from app.models.user import User
from app.security import current_user, hash_password
from app.services import totp


client = TestClient(app)
PASSWORD = "AuthenticatorPassphrase-42!"
RFC_KEY = b"12345678901234567890"


# --- the algorithm (no database) -------------------------------------------


@pytest.mark.no_db
def test_hotp_matches_the_rfc_4226_test_vectors():
    expected = ["755224", "287082", "359152", "969429", "338314",
                "254676", "287922", "162583", "399871", "520489"]

    assert [totp.hotp(RFC_KEY, counter) for counter in range(10)] == expected


@pytest.mark.no_db
@pytest.mark.parametrize(
    ("unix_time", "expected"),
    [
        (59, "94287082"),
        (1111111109, "07081804"),
        (1111111111, "14050471"),
        (1234567890, "89005924"),
        (2000000000, "69279037"),
        (20000000000, "65353130"),
    ],
)
def test_totp_matches_the_rfc_6238_sha1_test_vectors(unix_time, expected):
    assert totp.hotp(RFC_KEY, totp.counter_at(unix_time), digits=8) == expected


@pytest.mark.no_db
def test_totp_matches_the_rfc_6238_sha256_vector_when_asked_for_it():
    key = b"12345678901234567890123456789012"

    assert totp.hotp(key, totp.counter_at(59), digits=8, digest=hashlib.sha256) == "46119246"


@pytest.mark.no_db
def test_a_code_is_accepted_one_step_either_side_and_no_further():
    secret = totp.generate_secret()
    now = 1_800_000_015.0
    step = totp.counter_at(now)
    code_for = lambda offset: totp.totp(secret, at=now + offset * totp.PERIOD_SECONDS)

    assert totp.matching_counter(secret, code_for(0), at=now) == step
    assert totp.matching_counter(secret, code_for(-1), at=now) == step - 1
    assert totp.matching_counter(secret, code_for(1), at=now) == step + 1
    assert totp.matching_counter(secret, code_for(-2), at=now) is None
    assert totp.matching_counter(secret, code_for(2), at=now) is None


@pytest.mark.no_db
def test_a_code_cannot_be_replayed_inside_its_window():
    secret = totp.generate_secret()
    now = 1_800_000_015.0
    step = totp.counter_at(now)
    code = totp.totp(secret, at=now)

    assert totp.matching_counter(secret, code, at=now, last_counter=step - 1) == step
    assert totp.matching_counter(secret, code, at=now, last_counter=step) is None
    assert totp.matching_counter(secret, code, at=now, last_counter=step + 1) is None


@pytest.mark.no_db
@pytest.mark.parametrize("code", ["", "12345", "1234567", "12345a", "١٢٣٤٥٦", " 123456"])
def test_malformed_codes_never_match(code):
    assert totp.matching_counter(totp.generate_secret(), code) is None


@pytest.mark.no_db
def test_secrets_are_encrypted_at_rest_and_tampering_is_detected():
    secret = totp.generate_secret()
    stored = totp.encrypt_secret(secret)

    assert len(secret) == 32 and secret not in stored
    assert totp.decrypt_secret(stored) == secret
    assert totp.encrypt_secret(secret) != stored  # Fernet is randomised
    with pytest.raises(totp.TotpSecretUnreadable):
        totp.decrypt_secret(stored[:-4] + "AAAA")
    with pytest.raises(totp.TotpSecretUnreadable):
        totp.decrypt_secret("not a token")


@pytest.mark.no_db
def test_provisioning_uri_and_qr_code():
    uri = totp.provisioning_uri("JBSWY3DPEHPK3PXP", "alice@example.test")

    assert uri == (
        "otpauth://totp/CyberShield%20SOC%3Aalice%40example.test"
        "?secret=JBSWY3DPEHPK3PXP&issuer=CyberShield%20SOC&algorithm=SHA1&digits=6&period=30"
    )
    svg = totp.qr_svg(uri)
    assert svg.startswith('<svg xmlns="http://www.w3.org/2000/svg"') and svg.endswith("</svg>")
    # The top-left finder pattern: a 7-module bar starting after the quiet zone.
    assert "M4 4h7v1h-7z" in svg
    assert "<script" not in svg


@pytest.mark.no_db
def test_recovery_codes_are_distinct_and_normalise_for_comparison():
    codes = totp.generate_recovery_codes()

    assert len(codes) == len(set(codes)) == totp.RECOVERY_CODE_COUNT
    assert all(len(code) == 11 and code[5] == "-" for code in codes)
    spoken = codes[0].upper().replace("-", " ")
    assert totp.normalize_recovery_code(spoken) == codes[0].replace("-", "")
    assert totp.normalize_recovery_code("123456") is None
    assert totp.normalize_recovery_code("abcde-fghj0") is None  # 0 is not in the alphabet
    assert len(totp.hash_recovery_code("abcdefghjk")) == 64


# --- the flow --------------------------------------------------------------


@pytest.fixture(autouse=True)
def clean_state():
    client.cookies.clear()
    yield
    client.cookies.clear()
    app.dependency_overrides.pop(current_user, None)
    app.dependency_overrides.pop(get_otp_email_sender, None)


@pytest.fixture
def clock(monkeypatch):
    """Hold the TOTP time step still so codes cannot roll over mid-test."""

    step = totp.counter_at()
    monkeypatch.setattr(totp, "counter_at", lambda timestamp=None: step)

    def code(secret: str, offset: int = 0) -> str:
        return totp.hotp(totp._key_bytes(secret), step + offset)

    return code


@pytest.fixture
def mailbox():
    sent: list[str] = []

    def sender(*, to_email: str, code: str) -> None:
        sent.append(code)

    app.dependency_overrides[get_otp_email_sender] = lambda: sender
    return sent


def create_user(db: Session, role_name: str = "Analyst") -> User:
    role = db.scalar(select(Role).where(Role.name == role_name))
    if role is None:
        role = Role(name=role_name, description=f"{role_name} test role")
        db.add(role)
        db.flush()
    username = f"mfa-{uuid4().hex[:8]}"
    user = User(username=username, email=f"{username}@example.test", full_name="MFA Tester",
                password_hash=hash_password(PASSWORD), role_id=role.id, is_active=True)
    db.add(user)
    db.commit()
    return user


def sign_in_by_email(user: User, mailbox: list[str]) -> dict:
    login = client.post("/auth/login", json={"username": user.username, "password": PASSWORD})
    assert login.status_code == 200 and login.json()["method"] == "email", login.text
    verified = client.post("/auth/2fa/verify", json={"code": mailbox[-1]})
    assert verified.status_code == 200, verified.text
    return {"Authorization": f"Bearer {verified.json()['access_token']}"}


def enrol(user: User, mailbox: list[str], clock) -> tuple[dict, str, list[str]]:
    """Sign in by email, enrol an authenticator, return (headers, secret, recovery codes)."""

    headers = sign_in_by_email(user, mailbox)
    setup = client.post("/auth/mfa/totp/setup", headers=headers)
    assert setup.status_code == 200, setup.text
    secret = setup.json()["secret"]
    # Enrol with the previous step's code so this step's is still unused.
    enabled = client.post("/auth/mfa/totp/enable", headers=headers, json={"code": clock(secret, -1)})
    assert enabled.status_code == 200, enabled.text
    client.cookies.clear()
    return headers, secret, enabled.json()["recovery_codes"]


def audit_actions(db: Session, user: User) -> list[tuple[str, str]]:
    db.expire_all()
    return [
        (event.action, event.outcome)
        for event in db.scalars(
            select(AuditEvent)
            .where((AuditEvent.actor_user_id == user.id) | (AuditEvent.target_id == str(user.id)))
            .order_by(AuditEvent.id)
        )
    ]


def test_an_account_without_an_authenticator_reports_email_and_signs_in_as_before(db_session, mailbox):
    user = create_user(db_session)
    headers = sign_in_by_email(user, mailbox)

    state = client.get("/auth/mfa", headers=headers).json()

    assert state == {
        "success": True,
        "method": "email",
        "totp_enabled": False,
        "totp_enabled_at": None,
        "recovery_codes_remaining": 0,
    }


def test_setup_returns_the_secret_once_and_changes_nothing_until_confirmed(db_session, mailbox, clock):
    user = create_user(db_session)
    headers = sign_in_by_email(user, mailbox)

    setup = client.post("/auth/mfa/totp/setup", headers=headers).json()

    assert setup["otpauth_uri"].startswith("otpauth://totp/CyberShield%20SOC%3A")
    assert f"secret={setup['secret']}" in setup["otpauth_uri"]
    assert setup["qr_svg"].startswith("<svg")
    db_session.expire_all()
    stored = db_session.get(User, user.id)
    assert stored.totp_secret and setup["secret"] not in stored.totp_secret
    assert stored.totp_enabled_at is None
    assert client.get("/auth/mfa", headers=headers).json()["method"] == "email"

    # Still an emailed code at the next sign-in.
    client.cookies.clear()
    assert client.post("/auth/login", json={"username": user.username, "password": PASSWORD}).json()["method"] == "email"


def test_a_wrong_code_does_not_enable_the_authenticator(db_session, mailbox, clock):
    user = create_user(db_session)
    headers = sign_in_by_email(user, mailbox)
    secret = client.post("/auth/mfa/totp/setup", headers=headers).json()["secret"]
    wrong = f"{(int(clock(secret)) + 1) % 1_000_000:06d}"

    response = client.post("/auth/mfa/totp/enable", headers=headers, json={"code": wrong})

    assert response.status_code == 400
    assert client.get("/auth/mfa", headers=headers).json()["totp_enabled"] is False
    assert ("auth.mfa.enroll", "FAILURE") in audit_actions(db_session, user)


def test_enabling_without_a_pending_setup_is_refused(db_session, mailbox):
    user = create_user(db_session)
    headers = sign_in_by_email(user, mailbox)

    assert client.post("/auth/mfa/totp/enable", headers=headers, json={"code": "123456"}).status_code == 409


def test_enrolling_switches_sign_in_to_the_authenticator_and_sends_no_email(db_session, mailbox, clock):
    user = create_user(db_session)
    headers, secret, recovery_codes = enrol(user, mailbox, clock)
    emails_before = len(mailbox)

    assert len(recovery_codes) == 8
    state = client.get("/auth/mfa", headers=headers).json()
    assert (state["method"], state["recovery_codes_remaining"]) == ("totp", 8)

    login = client.post("/auth/login", json={"username": user.username, "password": PASSWORD})
    assert login.status_code == 200
    assert login.json()["method"] == "totp"
    assert len(mailbox) == emails_before

    verified = client.post("/auth/2fa/verify", json={"code": clock(secret)})
    assert verified.status_code == 200, verified.text
    assert verified.json()["user"]["username"] == user.username
    assert client.get("/auth/me", headers={"Authorization": f"Bearer {verified.json()['access_token']}"}).status_code == 200

    actions = audit_actions(db_session, user)
    assert ("auth.mfa.enroll", "SUCCESS") in actions
    db_session.expire_all()
    last = db_session.scalars(
        select(AuditEvent).where(AuditEvent.actor_user_id == user.id, AuditEvent.action == "auth.login.second_factor")
        .order_by(AuditEvent.id.desc())
    ).first()
    assert last.detail["factor"] == "totp"


def test_a_used_authenticator_code_cannot_sign_in_twice(db_session, mailbox, clock):
    user = create_user(db_session)
    _, secret, _ = enrol(user, mailbox, clock)
    code = clock(secret)

    client.post("/auth/login", json={"username": user.username, "password": PASSWORD})
    assert client.post("/auth/2fa/verify", json={"code": code}).status_code == 200

    client.cookies.clear()
    client.post("/auth/login", json={"username": user.username, "password": PASSWORD})
    replay = client.post("/auth/2fa/verify", json={"code": code})
    assert replay.status_code == 401
    # The next step's code is new, so it works.
    assert client.post("/auth/2fa/verify", json={"code": clock(secret, 1)}).status_code == 200


def test_wrong_authenticator_codes_hit_the_same_attempt_lockout(db_session, mailbox, clock):
    user = create_user(db_session)
    _, secret, _ = enrol(user, mailbox, clock)
    wrong = f"{(int(clock(secret)) + 1) % 1_000_000:06d}"

    client.post("/auth/login", json={"username": user.username, "password": PASSWORD})
    responses = [client.post("/auth/2fa/verify", json={"code": wrong}) for _ in range(5)]

    assert [r.status_code for r in responses] == [401] * 5
    assert "Too many incorrect attempts" in responses[-1].json()["detail"]
    # Locked: even the right code is refused for this pending sign-in.
    assert client.post("/auth/2fa/verify", json={"code": clock(secret)}).status_code == 401


def test_an_emailed_code_is_not_accepted_for_an_authenticator_account(db_session, mailbox, clock):
    user = create_user(db_session)
    enrol(user, mailbox, clock)

    client.post("/auth/login", json={"username": user.username, "password": PASSWORD})

    assert client.post("/auth/2fa/verify", json={"code": mailbox[-1]}).status_code == 401
    resend = client.post("/auth/2fa/resend")
    assert resend.status_code == 400
    assert "authenticator app" in resend.json()["detail"]


def test_a_recovery_code_signs_in_once(db_session, mailbox, clock):
    user = create_user(db_session)
    headers, _, recovery_codes = enrol(user, mailbox, clock)

    client.post("/auth/login", json={"username": user.username, "password": PASSWORD})
    first = client.post("/auth/2fa/verify", json={"code": recovery_codes[0].upper()})
    assert first.status_code == 200, first.text
    assert client.get("/auth/mfa", headers=headers).json()["recovery_codes_remaining"] == 7

    client.cookies.clear()
    client.post("/auth/login", json={"username": user.username, "password": PASSWORD})
    assert client.post("/auth/2fa/verify", json={"code": recovery_codes[0]}).status_code == 401
    assert client.post("/auth/2fa/verify", json={"code": recovery_codes[1]}).status_code == 200

    stored = db_session.scalars(select(MfaRecoveryCode).where(MfaRecoveryCode.user_id == user.id)).all()
    assert all(len(row.code_hash) == 64 for row in stored)
    assert not any(code.replace("-", "") in row.code_hash for row in stored for code in recovery_codes)


def test_setup_is_refused_while_an_authenticator_is_active(db_session, mailbox, clock):
    user = create_user(db_session)
    headers, _, _ = enrol(user, mailbox, clock)

    assert client.post("/auth/mfa/totp/setup", headers=headers).status_code == 409


def test_recovery_codes_can_be_regenerated_with_a_current_code(db_session, mailbox, clock):
    user = create_user(db_session)
    headers, secret, old_codes = enrol(user, mailbox, clock)

    refused = client.post("/auth/mfa/recovery-codes", headers=headers, json={"code": old_codes[0]})
    assert refused.status_code == 400  # a recovery code cannot mint more recovery codes
    assert client.get("/auth/mfa", headers=headers).json()["recovery_codes_remaining"] == 8

    regenerated = client.post("/auth/mfa/recovery-codes", headers=headers, json={"code": clock(secret)})
    assert regenerated.status_code == 200, regenerated.text
    new_codes = regenerated.json()["recovery_codes"]
    assert len(new_codes) == 8 and not set(new_codes) & set(old_codes)

    client.post("/auth/login", json={"username": user.username, "password": PASSWORD})
    assert client.post("/auth/2fa/verify", json={"code": old_codes[1]}).status_code == 401
    assert client.post("/auth/2fa/verify", json={"code": new_codes[0]}).status_code == 200


def test_disabling_needs_the_password_and_a_code_then_email_codes_return(db_session, mailbox, clock):
    user = create_user(db_session)
    headers, secret, _ = enrol(user, mailbox, clock)

    wrong_password = client.post(
        "/auth/mfa/totp/disable", headers=headers, json={"password": "nope", "code": clock(secret)}
    )
    wrong_code = client.post(
        "/auth/mfa/totp/disable", headers=headers, json={"password": PASSWORD, "code": "000000"}
    )
    assert (wrong_password.status_code, wrong_code.status_code) == (400, 400)
    assert wrong_password.json()["detail"] == wrong_code.json()["detail"]
    assert client.get("/auth/mfa", headers=headers).json()["totp_enabled"] is True

    # The wrong-password attempt must not have burned the code.
    disabled = client.post(
        "/auth/mfa/totp/disable", headers=headers, json={"password": PASSWORD, "code": clock(secret)}
    )
    assert disabled.status_code == 200, disabled.text
    assert disabled.json()["method"] == "email"

    db_session.expire_all()
    stored = db_session.get(User, user.id)
    assert (stored.totp_secret, stored.totp_enabled_at, stored.totp_last_counter) == (None, None, None)
    assert db_session.scalars(select(MfaRecoveryCode).where(MfaRecoveryCode.user_id == user.id)).all() == []
    assert client.post("/auth/login", json={"username": user.username, "password": PASSWORD}).json()["method"] == "email"
    actions = audit_actions(db_session, user)
    assert actions.count(("auth.mfa.disable", "FAILURE")) == 2
    assert ("auth.mfa.disable", "SUCCESS") in actions


def test_an_admin_can_reset_a_locked_out_users_authenticator(db_session, mailbox, clock):
    user = create_user(db_session)
    headers, _, _ = enrol(user, mailbox, clock)
    admin = create_user(db_session, "Admin")
    admin_headers = sign_in_by_email(admin, mailbox)
    client.cookies.clear()

    listed = client.get("/users", headers=admin_headers).json()["users"]
    assert next(row for row in listed if row["id"] == user.id)["mfa_method"] == "totp"

    reset = client.post(f"/users/{user.id}/mfa/reset", headers=admin_headers)

    assert reset.status_code == 200, reset.text
    assert reset.json()["user"]["mfa_method"] == "email"
    assert reset.json()["sessions_revoked"] >= 1
    login = client.post("/auth/login", json={"username": user.username, "password": PASSWORD})
    assert login.json()["method"] == "email"
    assert ("user.mfa.reset", "SUCCESS") in audit_actions(db_session, user)


def test_only_admins_can_reset_someone_elses_authenticator(db_session, mailbox, clock):
    user = create_user(db_session)
    analyst = create_user(db_session)
    headers = sign_in_by_email(analyst, mailbox)

    assert client.post(f"/users/{user.id}/mfa/reset", headers=headers).status_code == 403


def test_an_unreadable_secret_falls_back_to_emailed_codes(db_session, mailbox, clock):
    user = create_user(db_session)
    enrol(user, mailbox, clock)
    stored = db_session.get(User, user.id)
    stored.totp_secret = "written-under-a-different-server-key"
    db_session.commit()

    login = client.post("/auth/login", json={"username": user.username, "password": PASSWORD})

    assert login.json()["method"] == "email"
    assert client.post("/auth/2fa/verify", json={"code": mailbox[-1]}).status_code == 200


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("get", "/auth/mfa"),
        ("post", "/auth/mfa/totp/setup"),
        ("post", "/auth/mfa/totp/enable"),
        ("post", "/auth/mfa/totp/disable"),
        ("post", "/auth/mfa/recovery-codes"),
    ],
)
def test_mfa_endpoints_require_sign_in(method, path):
    response = getattr(client, method)(path, **({"json": {"code": "123456", "password": "x"}} if method == "post" else {}))

    assert response.status_code == 401
