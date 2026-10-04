from datetime import datetime, timezone
from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.models.alert import Alert
from app.models.correlation import AlertEventLink, CorrelationGroup, CorrelationGroupEvent
from app.models.log import Log


def source_rows(db):
    upload_id = uuid4()
    log = Log(upload_id=upload_id, source_filename="evidence.csv", source_format="csv", line_number=1, raw_message="original evidence", parsed_data={})
    alert = Alert(upload_id=upload_id, rule="brute_force_login", title="Evidence", severity="HIGH", description="Evidence", matched_line_numbers=[1])
    db.add_all([log, alert])
    db.flush()
    return log, alert


def test_evidence_link_is_unique_and_restricts_source_deletion(db_session):
    log, alert = source_rows(db_session)
    db_session.add(AlertEventLink(alert_id=alert.id, log_id=log.id))
    db_session.flush()
    with pytest.raises(IntegrityError), db_session.begin_nested():
        db_session.add(AlertEventLink(alert_id=alert.id, log_id=log.id))
        db_session.flush()
    with pytest.raises(IntegrityError), db_session.begin_nested():
        db_session.delete(log)
        db_session.flush()
    assert db_session.get(Log, log.id).raw_message == "original evidence"
    alert.status = "CLOSED"
    db_session.flush()
    assert db_session.get(Log, log.id).raw_message == "original evidence"


def test_deleting_derived_group_preserves_original_evidence(db_session):
    log, _ = source_rows(db_session)
    now = datetime.now(timezone.utc)
    group = CorrelationGroup(fingerprint=uuid4().hex, group_type="entity_window", entity_type="source_ip", entity_value="192.0.2.1", first_seen=now, last_seen=now, window_seconds=60, severity="HIGH", reason="same source", rule_key="brute_force_login", rule_context={})
    db_session.add(group)
    db_session.flush()
    db_session.add(CorrelationGroupEvent(group_id=group.id, log_id=log.id))
    db_session.flush()
    db_session.delete(group)
    db_session.flush()
    assert db_session.get(Log, log.id).raw_message == "original evidence"
    assert db_session.scalar(select(CorrelationGroupEvent).where(CorrelationGroupEvent.log_id == log.id)) is None


def test_invalid_group_constraints_are_enforced(db_session):
    now = datetime.now(timezone.utc)
    with pytest.raises(IntegrityError), db_session.begin_nested():
        db_session.add(CorrelationGroup(fingerprint=uuid4().hex, group_type="entity_window", entity_type="source_ip", entity_value="192.0.2.1", first_seen=now, last_seen=now, window_seconds=0, severity="HIGH", confidence=101, reason="invalid", rule_key="test", rule_context={}))
        db_session.flush()
