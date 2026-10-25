"""Live upgrade/downgrade coverage for source metadata on existing batches."""
from pathlib import Path
from uuid import uuid4

from alembic import command
from alembic.config import Config
import pytest
from sqlalchemy import inspect, text

from app.db.session import engine

pytestmark = pytest.mark.no_db


def test_source_metadata_migration_preserves_legacy_batches():
    schema = "ingestion_migration_" + uuid4().hex
    identity = uuid4()
    with engine.connect() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema}"'))
        connection.execute(text(f'SET search_path TO "{schema}"'))
        connection.commit()
        config = Config(str(Path(__file__).resolve().parents[1] / "alembic.ini"))
        config.attributes.update(connection=connection, version_table_schema=schema)
        try:
            command.upgrade(config, "s604_assistant_messages")
            connection.execute(text("INSERT INTO upload_batches(upload_id,source_filename,source_format,size_bytes) VALUES(:id,'legacy.log','syslog',42)"), {"id": identity})
            connection.commit()
            command.upgrade(config, "head")
            row = connection.execute(text("SELECT source_filename,size_bytes,source_name,source_type,source_host,ingested_by FROM upload_batches WHERE upload_id=:id"), {"id": identity}).one()
            assert tuple(row) == ("legacy.log", 42, None, None, None, None)
            connection.commit()
            command.downgrade(config, "s604_assistant_messages")
            columns = {column["name"] for column in inspect(connection).get_columns("upload_batches", schema=schema)}
            assert "source_name" not in columns
            assert connection.execute(text("SELECT source_filename FROM upload_batches WHERE upload_id=:id"), {"id": identity}).scalar_one() == "legacy.log"
            connection.commit()
            command.upgrade(config, "head")
            assert connection.execute(text("SELECT count(*) FROM upload_batches WHERE upload_id=:id"), {"id": identity}).scalar_one() == 1
            connection.commit()
        finally:
            connection.rollback()
            connection.execute(text("SET search_path TO public"))
            connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
            connection.commit()
