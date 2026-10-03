"""Independent PostgreSQL connections prove locks prevent concurrent lost updates."""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Barrier
from uuid import uuid4

from alembic import command
from alembic.config import Config
from fastapi import HTTPException
import pytest
from sqlalchemy import create_engine, func, select, text
from sqlalchemy.orm import sessionmaker

from app.core.config import settings
from app.db.session import engine
from app.models.alert import Alert
from app.models.auth_session import AuthSession
from app.models.incident import Incident
from app.models.role import Role
from app.models.otp_verification import OtpVerification
from app.models.password_reset_token import PasswordResetToken
from app.models.user import User
from app.models.workflow import IncidentAlertLink, WorkflowEvent
from app.repositories.incident_repository import (
    IncidentAlreadyExistsError,
    create_incident_from_alert,
)
from app.repositories.otp_repository import (
    OtpResendCooldownError,
    OtpVerifyError,
    create_otp_challenge,
    resend_otp_challenge,
    verify_otp_challenge,
)
from app.repositories.password_reset_repository import (
    PasswordResetTokenInvalidError,
    consume_reset_token,
    create_reset_challenge,
)
from app.security import create_refresh_token, rotate_refresh_token
from app.services.incident_workflow import link_alert, update_incident

pytestmark = pytest.mark.no_db


@pytest.fixture
def concurrent_database():
    schema = "sprint6_race_" + uuid4().hex
    with engine.begin() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    local = create_engine(
        settings.database_url,
        connect_args={"options": f"-csearch_path={schema}", "connect_timeout": 5},
    )
    factory = sessionmaker(local, autoflush=False, expire_on_commit=False)
    try:
        with local.connect() as connection:
            config = Config(str(Path(__file__).resolve().parents[1] / "alembic.ini"))
            config.attributes.update(connection=connection, version_table_schema=schema)
            command.upgrade(config, "head")
        with factory() as session:
            role = session.scalar(select(Role).where(Role.name == "Analyst"))
            actor = User(
                role=role,
                username="race_analyst",
                email="race@example.test",
                password_hash="unused",
            )
            alerts = [
                Alert(
                    upload_id=uuid4(),
                    rule="test",
                    title=str(i),
                    severity="HIGH",
                    description="Race evidence",
                )
                for i in range(3)
            ]
            session.add_all([actor, *alerts])
            session.commit()
            actor_id, ids = actor.id, [a.id for a in alerts]
        yield factory, actor_id, ids
    finally:
        local.dispose()
        with engine.begin() as connection:
            connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))


def race(factory, actions):
    barrier = Barrier(2)

    def worker(action):
        with factory() as session:
            session.execute(text("SET LOCAL lock_timeout = '5s'"))
            barrier.wait(timeout=5)
            try:
                action(session)
                session.commit()
                return 200
            except (HTTPException, IncidentAlreadyExistsError) as exc:
                session.rollback()
                return exc.status_code if isinstance(exc, HTTPException) else 409

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(worker, actions))
    assert sorted(results) == [200, 409]


def test_two_escalations_create_only_one_incident(concurrent_database):
    factory, actor, alerts = concurrent_database
    race(
        factory,
        [
            lambda session: create_incident_from_alert(
                session, alert_id=alerts[0], created_by_user_id=actor
            )
        ]
        * 2,
    )
    with factory() as session:
        assert session.scalar(select(func.count()).select_from(Incident)) == 1
        assert session.scalar(select(func.count()).select_from(IncidentAlertLink)) == 1
        assert (
            session.scalar(
                select(func.count())
                .select_from(WorkflowEvent)
                .where(WorkflowEvent.incident_id.is_not(None))
            )
            == 1
        )


def test_stale_concurrent_update_is_rejected_without_extra_history(concurrent_database):
    factory, actor, alerts = concurrent_database
    with factory() as session:
        incident = create_incident_from_alert(
            session, alert_id=alerts[0], created_by_user_id=actor
        )
        identity = incident.id
        session.commit()
    race(
        factory,
        [
            lambda session: update_incident(
                session, identity, {"priority": "LOW", "expected_version": 1}, actor
            ),
            lambda session: update_incident(
                session,
                identity,
                {"priority": "CRITICAL", "expected_version": 1},
                actor,
            ),
        ],
    )
    with factory() as session:
        assert session.get(Incident, identity).version == 2
        assert (
            session.scalar(
                select(func.count())
                .select_from(WorkflowEvent)
                .where(
                    WorkflowEvent.incident_id == identity,
                    WorkflowEvent.event_type == "UPDATED",
                )
            )
            == 1
        )


def test_one_alert_cannot_be_linked_concurrently_to_two_incidents(concurrent_database):
    factory, actor, alerts = concurrent_database
    with factory() as session:
        incidents = [
            create_incident_from_alert(
                session, alert_id=identity, created_by_user_id=actor
            )
            for identity in alerts[:2]
        ]
        first, second = [i.id for i in incidents]
        session.commit()
    race(
        factory,
        [
            lambda session: link_alert(session, first, alerts[2], actor),
            lambda session: link_alert(session, second, alerts[2], actor),
        ],
    )
    with factory() as session:
        assert (
            session.scalar(
                select(func.count())
                .select_from(IncidentAlertLink)
                .where(IncidentAlertLink.alert_id == alerts[2])
            )
            == 1
        )


def authentication_race(factory, actions):
    barrier = Barrier(len(actions))

    def worker(action):
        with factory() as session:
            session.execute(text("SET LOCAL lock_timeout = '5s'"))
            barrier.wait(timeout=5)
            try:
                result = action(session)
            except (
                OtpVerifyError,
                OtpResendCooldownError,
                PasswordResetTokenInvalidError,
            ):
                session.commit()  # Verification failures must persist attempt counts.
                return False
            session.commit()
            return result is not None

    with ThreadPoolExecutor(max_workers=len(actions)) as pool:
        return list(pool.map(worker, actions))


@pytest.mark.parametrize("kind", ["refresh", "otp", "password_reset"])
def test_authentication_tokens_cannot_be_reused_concurrently(concurrent_database, kind):
    factory, actor, _ = concurrent_database
    with factory() as session:
        user = session.get(User, actor)
        if kind == "refresh":
            token = create_refresh_token(session, user)
            action = lambda db: rotate_refresh_token(db, token)
            model = AuthSession
        elif kind == "otp":
            code, token = create_otp_challenge(session, user, remember_me=False)
            action = lambda db: verify_otp_challenge(db, token, code)
            model = OtpVerification
        else:
            token = create_reset_challenge(session, user)
            action = lambda db: consume_reset_token(db, token)
            model = PasswordResetToken
        session.commit()

    assert sorted(authentication_race(factory, [action, action])) == [False, True]
    with factory() as session:
        if kind == "refresh":
            assert (
                session.scalar(
                    select(func.count())
                    .select_from(model)
                    .where(model.revoked_at.is_(None))
                )
                == 1
            )
            assert session.scalar(select(func.count()).select_from(model)) == 2
        else:
            assert (
                session.scalar(
                    select(func.count()).select_from(model).where(model.used.is_(False))
                )
                == 0
            )


def test_concurrent_wrong_otp_attempts_enforce_the_limit(concurrent_database):
    factory, actor, _ = concurrent_database
    with factory() as session:
        code, token = create_otp_challenge(
            session, session.get(User, actor), remember_me=False
        )
        session.commit()
    wrong_code = "000000" if code != "000000" else "000001"
    action = lambda db: verify_otp_challenge(db, token, wrong_code)
    assert not any(
        authentication_race(factory, [action] * (settings.otp_max_attempts + 3))
    )
    with factory() as session:
        challenge = session.scalar(select(OtpVerification))
        assert challenge.attempt_count == settings.otp_max_attempts
        assert challenge.used is True


def test_concurrent_otp_resends_preserve_cooldown(concurrent_database):
    factory, actor, _ = concurrent_database
    with factory() as session:
        _, token = create_otp_challenge(
            session, session.get(User, actor), remember_me=False
        )
        challenge = session.scalar(select(OtpVerification))
        challenge.created_at = datetime.now(timezone.utc) - timedelta(
            seconds=settings.otp_resend_cooldown_seconds + 1
        )
        session.commit()
    action = lambda db: resend_otp_challenge(db, token)
    assert sorted(authentication_race(factory, [action, action])) == [False, True]
    with factory() as session:
        assert session.scalar(select(func.count()).select_from(OtpVerification)) == 2
        assert (
            session.scalar(
                select(func.count())
                .select_from(OtpVerification)
                .where(OtpVerification.used.is_(False))
            )
            == 1
        )


def test_concurrent_reset_requests_leave_only_one_active_token(concurrent_database):
    factory, actor, _ = concurrent_database
    action = lambda db: create_reset_challenge(db, db.get(User, actor))
    assert all(authentication_race(factory, [action, action]))
    with factory() as session:
        assert session.scalar(select(func.count()).select_from(PasswordResetToken)) == 2
        assert (
            session.scalar(
                select(func.count())
                .select_from(PasswordResetToken)
                .where(PasswordResetToken.used.is_(False))
            )
            == 1
        )
