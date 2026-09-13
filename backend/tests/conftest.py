"""Shared, rollback-only database isolation for the backend test suite."""

from __future__ import annotations

import sys
from collections.abc import Generator
from pathlib import Path

import pytest
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.db.session import engine, get_db
from app.main import app


BACKEND_ROOT = Path(__file__).resolve().parents[1]
ALEMBIC_CONFIG = BACKEND_ROOT / "alembic.ini"


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "no_db: skip the autouse database dependency override for pure unit tests",
    )
    config.addinivalue_line(
        "markers",
        "db: require PostgreSQL even when a containing module is marked no_db",
    )


@pytest.fixture(scope="session")
def database_preflight() -> None:
    """Fail once when PostgreSQL is unreachable or its schema is stale."""

    try:
        alembic_config = Config(str(ALEMBIC_CONFIG))
        expected_heads = set(ScriptDirectory.from_config(alembic_config).get_heads())
        if len(expected_heads) != 1:
            pytest.exit(
                "Backend tests require a single Alembic head; found "
                f"{sorted(expected_heads)!r}.",
                returncode=2,
            )

        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
            applied_heads = set(
                connection.execute(text("SELECT version_num FROM alembic_version")).scalars()
            )
    except SQLAlchemyError as exc:
        pytest.exit(
            "PostgreSQL test preflight failed. From the repository root run "
            "`docker compose up -d --wait database`, then from backend run "
            "`.\\.venv\\Scripts\\python.exe -m alembic upgrade head`. "
            f"Database error: {exc}",
            returncode=2,
        )

    if applied_heads != expected_heads:
        pytest.exit(
            "The PostgreSQL test schema is not at the repository Alembic head "
            f"(database={sorted(applied_heads)!r}, expected={sorted(expected_heads)!r}). "
            "From backend run `.\\.venv\\Scripts\\python.exe -m alembic upgrade head`.",
            returncode=2,
        )


@pytest.fixture
def test_session_factory(
    database_preflight: None,
) -> Generator[sessionmaker[Session], None, None]:
    """Keep route-level commits inside an outer transaction we always undo."""

    connection = engine.connect()
    outer_transaction = connection.begin()
    factory = sessionmaker(
        bind=connection,
        class_=Session,
        autoflush=False,
        expire_on_commit=False,
        # API repositories deliberately commit. Savepoints let those commits
        # behave normally without escaping the test's outer transaction.
        join_transaction_mode="create_savepoint",
    )

    try:
        yield factory
    finally:
        if outer_transaction.is_active:
            outer_transaction.rollback()
        connection.close()


@pytest.fixture(autouse=True)
def isolate_route_database(request):
    """Route every API dependency through the rollback-only test connection."""

    if (
        request.node.get_closest_marker("no_db")
        and not request.node.get_closest_marker("db")
    ):
        yield
        return

    test_session_factory = request.getfixturevalue("test_session_factory")
    previous_override = app.dependency_overrides.get(get_db)

    def override_get_db():
        with test_session_factory() as session:
            yield session

    app.dependency_overrides[get_db] = override_get_db
    try:
        yield
    finally:
        if previous_override is None:
            app.dependency_overrides.pop(get_db, None)
        else:
            app.dependency_overrides[get_db] = previous_override


@pytest.fixture
def db_session(test_session_factory: sessionmaker[Session]):
    """Expose an isolated session for tests that need to arrange real rows."""

    with test_session_factory() as session:
        yield session
