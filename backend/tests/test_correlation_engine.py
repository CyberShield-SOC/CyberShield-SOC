import pytest

from app.detection.models import LogRecord
from app.services.correlation import CorrelationPolicy, EvidenceAlert, EvidenceEvent, correlate

pytestmark = pytest.mark.no_db


def event(identity, seconds=0, ip="192.0.2.1", user="alice", host="host-a", upload="batch-a", timestamp=None):
    return EvidenceEvent(id=identity, upload_id=upload, record=LogRecord(line_number=identity, timestamp=timestamp or f"2026-10-02T00:{seconds // 60:02d}:{seconds % 60:02d}Z", ip_address=ip, username=user, hostname=host))


def run(events, entity="source_ip", ids=None, cross=False, rule="rule-a", context=None):
    alerts = [EvidenceAlert(id=1, rule=rule, event_ids=tuple(ids if ids is not None else [e.id for e in events]), severity="HIGH", confidence=80)]
    policies = {rule: CorrelationPolicy(rule_key=rule, entity_type=entity, window_seconds=60, cross_upload=cross, rule_context=context or {})}
    return correlate(events, alerts, policies)


@pytest.mark.parametrize("entity,changed", [("source_ip", {"ip": "192.0.2.2"}), ("account", {"user": "bob"}), ("host", {"host": "host-b"})])
def test_matching_and_nonmatching_entities(entity, changed):
    assert len(run([event(1), event(2, 10)], entity)) == 1
    assert len(run([event(1), event(2, 10, **changed)], entity)) == 2


def test_inclusive_boundary_and_no_chained_time_drift():
    groups = run([event(1), event(2, 60), event(3, 61), event(4, 110)])
    assert [g.event_ids for g in groups] == [(1, 2), (3, 4)]
    assert all((g.last_seen - g.first_seen).total_seconds() <= 60 for g in groups)


def test_identity_duplicates_and_order_are_deterministic():
    items = [event(1), event(2, 20), event(3, 40)]
    assert run(items) == run([items[2], items[0], items[1], items[0]])
    assert len(run(items)[0].event_ids) == 3
    with pytest.raises(ValueError, match="Conflicting"):
        run([event(1), event(1, ip="192.0.2.2")])


def test_scope_and_rule_context_are_explicit():
    items = [event(1), event(2, 10, upload="batch-b")]
    assert len(run(items)) == 2
    assert len(run(items, cross=True)) == 1
    assert run(items)[0].fingerprint != run(items, context={"threshold": 8})[0].fingerprint
    alerts = [EvidenceAlert(id=1, rule="rule-a", event_ids=(1,), severity="LOW"), EvidenceAlert(id=2, rule="rule-b", event_ids=(2,), severity="HIGH")]
    policies = {key: CorrelationPolicy(rule_key=key, entity_type="source_ip") for key in ("rule-a", "rule-b")}
    assert len(correlate(items, alerts, policies)) == 2


def test_unrelated_events_and_unknown_entities_or_times_do_not_join():
    assert run([event(1), event(2, 1)], ids=[1])[0].event_ids == (1,)
    assert run([event(1, ip="Unknown")]) == []
    assert run([event(1, timestamp="unparseable")]) == []
    assert run([event(1, ip=None)]) == []


def test_hosts_normalize_but_accounts_preserve_case():
    assert len(run([event(1, host="HOST-A."), event(2, host="host-a")], "host")) == 1
    assert len(run([event(1, user="Alice"), event(2, user="alice")], "account")) == 2


def test_batch_scope_uses_only_exact_rule_matches():
    groups = run([event(1), event(2, ip="192.0.2.2"), event(3, user="bob")], "upload_batch", ids=[1, 2])
    assert groups[0].event_ids == (1, 2)


def test_ipv6_and_timezone_normalization_and_missing_policy():
    items = [event(1, ip="2001:0db8::1", timestamp="2026-10-02T01:00:00+01:00"), event(2, ip="2001:db8::1")]
    assert len(run(items)) == 1
    assert correlate(items, [EvidenceAlert(id=1, rule="disabled", event_ids=(1, 2), severity="HIGH")], {}) == []
