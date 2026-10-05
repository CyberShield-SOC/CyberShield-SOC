"""Migration cycles run in a private PostgreSQL schema, never the development schema."""
from pathlib import Path
from uuid import uuid4

from alembic import command
from alembic.config import Config
import pytest
from sqlalchemy import text

from app.db.session import engine

pytestmark = pytest.mark.no_db


def test_populated_legacy_upgrade_downgrade_and_reupgrade_preserve_evidence():
    schema = "sprint6_migration_" + uuid4().hex
    with engine.connect() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema}"'))
        connection.execute(text(f'SET search_path TO "{schema}"'))
        connection.commit()
        config = Config(str(Path(__file__).resolve().parents[1] / "alembic.ini"))
        config.attributes.update(connection=connection, version_table_schema=schema)
        try:
            command.upgrade(config, "f2a9c7e410b3")
            connection.execute(text("INSERT INTO users(id,role_id,username,email,password_hash) SELECT 1,id,'migration_analyst','migration@example.test','not-a-password' FROM roles WHERE name='Analyst'"))
            for identity, upload, raw in ((1, "00000000-0000-4000-8000-000000000001", "original raw evidence"), (2, "00000000-0000-4000-8000-000000000002", "different upload, same line")):
                connection.execute(text("INSERT INTO logs(id,upload_id,source_filename,source_format,line_number,raw_message) VALUES(:id,:upload,'legacy.csv','csv',1,:raw)"), {"id": identity, "upload": upload, "raw": raw})
            connection.execute(text("INSERT INTO alerts(id,upload_id,rule,title,severity,status,description,matched_line_numbers) VALUES(1,'00000000-0000-4000-8000-000000000001','brute_force_login','Legacy alert','HIGH','CLOSED','Legacy evidence',ARRAY[1,99])"))
            connection.execute(text("INSERT INTO incidents(id,source_alert_id,assigned_user_id,created_by_user_id,title,description,priority,status,resolved_at,response_playbook) VALUES(1,1,1,1,'Legacy incident','Preserve me','HIGH','RESOLVED','2026-09-01T12:00:00Z','{\"action\":\"review\"}')"))
            connection.execute(text("INSERT INTO notes(id,incident_id,author_user_id,title,body) VALUES(1,1,1,'Legacy note','Preserve the original note')"))
            connection.commit()
            queries = ["SELECT id,upload_id,line_number,raw_message,parsed_data FROM logs ORDER BY id", "SELECT id,source_alert_id,assigned_user_id,status,resolved_at,response_playbook FROM incidents", "SELECT id,incident_id,author_user_id,title,body FROM notes"]
            before = [connection.execute(text(query)).all() for query in queries]
            connection.commit()
            command.upgrade(config, "head")
            assert connection.execute(text("SELECT alert_id,log_id FROM alert_event_links")).all() == [(1, 1)]
            assert connection.execute(text("SELECT incident_id,alert_id FROM incident_alert_links")).all() == [(1, 1)]
            assert connection.execute(text("SELECT resolution_reason,resolved_by_user_id,resolved_by_name FROM incidents")).one() == ("LEGACY_UNKNOWN", None, None)
            assert connection.execute(text("SELECT actor_user_id FROM workflow_events WHERE incident_id=1")).scalar() is None
            assert connection.execute(text("SELECT investigation_state FROM alerts WHERE id=1")).scalar() == "LEGACY_CLOSED"
            assert [connection.execute(text(query)).all() for query in queries] == before
            connection.commit()
            command.downgrade(config, "f2a9c7e410b3")
            assert [connection.execute(text(query)).all() for query in queries] == before
            connection.commit()
            command.upgrade(config, "head")
            assert [connection.execute(text(query)).all() for query in queries] == before
            assert connection.execute(text("SELECT count(*) FROM alert_event_links")).scalar() == 1
            assert connection.execute(text("SELECT count(*) FROM incident_alert_links")).scalar() == 1
            connection.commit()
        finally:
            connection.rollback()
            connection.execute(text("SET search_path TO public"))
            connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
            connection.commit()
