"""Shared, rollback-only database isolation for the backend test suite."""

from __future__ import annotations

import sys
from collections.abc import Generator
from pathlib import Path

import pytest
from sqlalchemy.orm import Session, sessionmaker


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.db.session import engine, get_db
from app.main import app


@pytest.fixture
def test_session_factory() -> Generator[sessionmaker[Session], None, None]:
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
def isolate_route_database(test_session_factory: sessionmaker[Session]):
    """Route every API dependency through the rollback-only test connection."""

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
