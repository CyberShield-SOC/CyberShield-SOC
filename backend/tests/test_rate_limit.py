"""Request rate limiting: the limiter itself, then its effect on the API."""

from __future__ import annotations

import sys
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.requests import Request

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.core.config import settings
from app.core.rate_limit import SlidingWindowLimiter, client_ip, limiter
from app.dispatch.otp_email import get_otp_email_sender
from app.main import app
from app.models.role import Role
from app.models.user import User
from app.security import hash_password


client = TestClient(app)


@pytest.fixture
def limiting_on():
    limiter.reset()
    limiter.enabled = True
    yield
    limiter.reset()


@pytest.fixture(autouse=True)
def clean_client():
    client.cookies.clear()
    yield
    client.cookies.clear()
    app.dependency_overrides.pop(get_otp_email_sender, None)


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def make_request(headers: dict[str, str], peer: str = "10.0.0.9") -> Request:
    return Request(
        {
            "type": "http",
            "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
            "client": (peer, 1234),
        }
    )


@pytest.mark.no_db
def test_limiter_allows_up_to_the_limit_then_reports_the_wait():
    clock = FakeClock()
    window = SlidingWindowLimiter(clock=clock)

    assert [window.hit("k", 3, 60) for _ in range(3)] == [0, 0, 0]
    assert window.hit("k", 3, 60) == 60

    clock.now += 45
    assert window.hit("k", 3, 60) == 15


@pytest.mark.no_db
def test_limiter_window_slides_instead_of_resetting_all_at_once():
    clock = FakeClock()
    window = SlidingWindowLimiter(clock=clock)

    window.hit("k", 2, 60)
    clock.now += 40
    window.hit("k", 2, 60)
    clock.now += 21  # the first hit has aged out, the second has not

    assert window.hit("k", 2, 60) == 0
    assert window.hit("k", 2, 60) > 0


@pytest.mark.no_db
def test_limiter_keys_are_independent_and_a_blocked_call_is_not_counted():
    clock = FakeClock()
    window = SlidingWindowLimiter(clock=clock)

    window.hit("a", 1, 60)
    assert window.hit("a", 1, 60) > 0
    assert window.hit("b", 1, 60) == 0

    # Hammering while blocked must not push the unblock time further out.
    for _ in range(10):
        window.hit("a", 1, 60)
    clock.now += 60
    assert window.hit("a", 1, 60) == 0


@pytest.mark.no_db
def test_client_ip_uses_the_socket_peer_unless_a_proxy_header_is_configured(monkeypatch):
    request = make_request({"X-Real-IP": "203.0.113.7"})

    monkeypatch.setattr(settings, "rate_limit_client_ip_header", None)
    assert client_ip(request) == "10.0.0.9"

    monkeypatch.setattr(settings, "rate_limit_client_ip_header", "X-Real-IP")
    assert client_ip(request) == "203.0.113.7"


@pytest.mark.no_db
def test_client_ip_ignores_a_configured_header_that_is_not_an_address(monkeypatch):
    monkeypatch.setattr(settings, "rate_limit_client_ip_header", "X-Real-IP")

    assert client_ip(make_request({"X-Real-IP": "not-an-ip, 1.2.3.4"})) == "10.0.0.9"
    assert client_ip(make_request({})) == "10.0.0.9"


@pytest.mark.no_db
def test_global_limit_returns_429_with_retry_after(limiting_on, monkeypatch):
    monkeypatch.setattr(settings, "rate_limit_global_per_minute", 3)

    statuses = [client.get("/auth/me").status_code for _ in range(4)]
    blocked = client.get("/auth/me")

    assert statuses == [401, 401, 401, 429]
    assert blocked.status_code == 429
    assert 1 <= int(blocked.headers["retry-after"]) <= 60
    assert "Too many requests" in blocked.json()["detail"]
    # Security headers still wrap a rejected request.
    assert blocked.headers["x-content-type-options"] == "nosniff"


@pytest.mark.no_db
def test_health_probe_is_exempt_from_the_global_limit(limiting_on, monkeypatch):
    monkeypatch.setattr(settings, "rate_limit_global_per_minute", 1)

    assert [client.get("/health").status_code for _ in range(5)] == [200] * 5


@pytest.mark.no_db
def test_disabling_rate_limiting_in_settings_lifts_every_limit(limiting_on, monkeypatch):
    monkeypatch.setattr(settings, "rate_limit_global_per_minute", 1)
    monkeypatch.setattr(settings, "rate_limit_enabled", False)

    assert [client.get("/auth/me").status_code for _ in range(4)] == [401] * 4


def _create_user(db_session: Session) -> tuple[User, str]:
    role = db_session.scalar(select(Role).where(Role.name == "Analyst"))
    if role is None:
        role = Role(name="Analyst", description="Analyst test role")
        db_session.add(role)
        db_session.flush()
    username = f"limit-{uuid4().hex[:8]}"
    password = "RateLimitPassphrase-42!"
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


def _login(username: str, password: str):
    return client.post("/auth/login", json={"username": username, "password": password})


def _silence_otp_email() -> None:
    app.dependency_overrides[get_otp_email_sender] = lambda: lambda **_: None


def test_repeated_wrong_passwords_lock_the_account_out_even_with_the_right_one(
    limiting_on, monkeypatch, db_session
):
    monkeypatch.setattr(settings, "rate_limit_login_failures", 3)
    _silence_otp_email()
    user, password = _create_user(db_session)

    wrong = [_login(user.username, "wrong-password").status_code for _ in range(3)]
    locked = _login(user.username, password)

    assert wrong == [401, 401, 401]
    assert locked.status_code == 429
    assert int(locked.headers["retry-after"]) > 0


def test_lockout_is_keyed_on_the_identifier_not_on_whether_the_account_exists(
    limiting_on, monkeypatch
):
    monkeypatch.setattr(settings, "rate_limit_login_failures", 2)
    ghost = f"nobody-{uuid4().hex[:8]}"

    statuses = [_login(ghost, "wrong-password").status_code for _ in range(3)]

    assert statuses == [401, 401, 429]


def test_a_successful_login_clears_earlier_failures(limiting_on, monkeypatch, db_session):
    monkeypatch.setattr(settings, "rate_limit_login_failures", 3)
    _silence_otp_email()
    user, password = _create_user(db_session)

    for _ in range(2):
        _login(user.username, "wrong-password")
    assert _login(user.username, password).status_code == 200
    after = [_login(user.username, "wrong-password").status_code for _ in range(2)]

    assert after == [401, 401]


def test_login_attempts_are_capped_per_address(limiting_on, monkeypatch):
    monkeypatch.setattr(settings, "rate_limit_login_per_minute", 2)
    monkeypatch.setattr(settings, "rate_limit_login_failures", 100)

    statuses = [
        _login(f"nobody-{uuid4().hex[:8]}", "wrong-password").status_code
        for _ in range(3)
    ]

    assert statuses == [401, 401, 429]


def test_unauthenticated_token_endpoints_share_a_per_address_budget(
    limiting_on, monkeypatch
):
    monkeypatch.setattr(settings, "rate_limit_auth_per_minute", 2)

    first = client.post("/auth/forgot-password", json={"email": "a@example.test"})
    second = client.post("/auth/2fa/verify", json={"code": "123456"})
    third = client.post("/auth/forgot-password", json={"email": "b@example.test"})

    assert first.status_code == 200
    assert second.status_code == 401
    assert third.status_code == 429
