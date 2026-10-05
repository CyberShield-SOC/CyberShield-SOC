"""Structured correlation fixtures for Sprint 6 (KK-01).

Every fixture declares, explicitly and independently of the engine:

* input records        -> ``events`` and ``alerts`` (plus the ``policies`` in force)
* expected group(s)    -> ``expected_groups``
* expected evidence    -> the ``event_ids`` / ``alert_ids`` of each expected group;
                          each id is one evidence link from the group
* expected nonmatches  -> ``expected_nonmatches``: pairs of event ids that must
                          never land in the same group
* window behavior      -> ``window_behavior``: plain-English statement of what the
                          time window does in this case

The documented engine rules these fixtures encode (see
``app/services/correlation.py``):

* windows are anchored at their first event and inclusive at both ends
  (``last - first <= window_seconds``); they never chain/drift,
* grouping is partitioned per (rule policy, entity, upload scope), so two
  different rules never merge even for the same entity,
* repeated references to one event id collapse to a single evidence link,
* events with a missing/unknown/invalid entity or an unparseable timestamp are
  skipped rather than guessed at.

All timestamps are offsets in seconds from ``T0`` so boundary cases read
directly off the fixture.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from app.detection.models import LogRecord
from app.services.correlation import CorrelationPolicy, EvidenceAlert, EvidenceEvent

T0 = datetime(2026, 10, 2, 0, 0, 0, tzinfo=timezone.utc)
WINDOW = 300  # seconds; the default window used unless a fixture overrides it

CATEGORIES = ("positive", "negative", "duplicate", "boundary")


@dataclass(frozen=True)
class ExpectedGroup:
    rule_key: str
    entity_type: str
    entity_value: str
    event_ids: tuple[int, ...]
    alert_ids: tuple[int, ...]

    @property
    def key(self) -> tuple:
        return (self.rule_key, self.entity_type, self.entity_value, self.event_ids, self.alert_ids)


@dataclass(frozen=True)
class CorrelationFixture:
    name: str
    category: str
    description: str
    window_behavior: str
    events: tuple[EvidenceEvent, ...]
    alerts: tuple[EvidenceAlert, ...]
    policies: dict
    expected_groups: tuple[ExpectedGroup, ...]
    expected_nonmatches: tuple[tuple[int, int], ...] = ()


# --------------------------------------------------------------------------- helpers
def ev(
    identity: int,
    offset: int = 0,
    *,
    ip: str | None = "192.0.2.10",
    user: str | None = "alice",
    host: str | None = "host-a",
    upload: str = "batch-a",
    event_type: str = "login_attempt",
    status: str = "FAILED",
    timestamp: str | None = None,
) -> EvidenceEvent:
    stamp = timestamp or (T0 + timedelta(seconds=offset)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return EvidenceEvent(
        id=identity,
        upload_id=upload,
        record=LogRecord(
            line_number=identity,
            timestamp=stamp,
            ip_address=ip,
            username=user,
            hostname=host,
            event_type=event_type,
            status=status,
        ),
    )


def alert(identity: int, rule: str, event_ids, severity: str = "HIGH", confidence: int = 80) -> EvidenceAlert:
    return EvidenceAlert(
        id=identity, rule=rule, event_ids=tuple(event_ids), severity=severity, confidence=confidence
    )


def policy(rule: str, entity: str = "source_ip", **overrides) -> dict:
    return {rule: CorrelationPolicy(rule_key=rule, entity_type=entity, window_seconds=WINDOW, **overrides)}


def group(rule: str, entity_type: str, value: str, events, alerts) -> ExpectedGroup:
    return ExpectedGroup(rule, entity_type, value, tuple(events), tuple(alerts))


# --------------------------------------------------------------------------- fixtures
def _build() -> tuple[CorrelationFixture, ...]:
    fixtures: list[CorrelationFixture] = []
    add = fixtures.append

    # ---- positive: activity that SHOULD correlate ---------------------------------
    add(CorrelationFixture(
        "same_source_ip_in_window", "positive",
        "Three failed logins from one IP within the window form one group.",
        "All events fall within 120s of the first; window is 300s.",
        (ev(1, 0), ev(2, 60), ev(3, 120)),
        (alert(1, "brute_force", [1, 2, 3]),),
        policy("brute_force"),
        (group("brute_force", "source_ip", "192.0.2.10", [1, 2, 3], [1]),),
    ))
    add(CorrelationFixture(
        "same_username_in_window", "positive",
        "One account seen from different IPs and hosts groups under an account policy.",
        "Events at 0/90/180s, inside the 300s window.",
        (
            ev(1, 0, ip="192.0.2.11", host="host-a"),
            ev(2, 90, ip="192.0.2.12", host="host-b"),
            ev(3, 180, ip="192.0.2.13", host="host-c"),
        ),
        (alert(1, "multi_ip_login", [1, 2, 3]),),
        policy("multi_ip_login", "account"),
        (group("multi_ip_login", "account", "alice", [1, 2, 3], [1]),),
    ))
    add(CorrelationFixture(
        "same_host_in_window", "positive",
        "Activity from different users and IPs on one host groups under a host policy.",
        "Events at 0/100/200s, inside the 300s window.",
        (
            ev(1, 0, ip="192.0.2.21", user="alice", host="web-01"),
            ev(2, 100, ip="192.0.2.22", user="bob", host="web-01"),
            ev(3, 200, ip="192.0.2.23", user="carol", host="web-01"),
        ),
        (alert(1, "log_tampering", [1, 2, 3]),),
        policy("log_tampering", "host"),
        (group("log_tampering", "host", "web-01", [1, 2, 3], [1]),),
    ))
    add(CorrelationFixture(
        "suspicious_multi_event_brute_force_then_success", "positive",
        "Six failures then a success and a sudo from one IP: two rules, two rule-scoped "
        "groups; unrelated benign activity from another IP stays out of every group.",
        "Failures span 50s; success at 80s and sudo at 120s; window is 300s.",
        (
            *(ev(i, (i - 1) * 10, ip="203.0.113.50", user="mallory") for i in range(1, 7)),
            ev(7, 80, ip="203.0.113.50", user="mallory", status="SUCCESS"),
            ev(8, 120, ip="203.0.113.50", user="mallory", event_type="privilege_escalation", status="SUCCESS"),
            ev(20, 30, ip="198.51.100.7", user="dana", status="SUCCESS"),
            ev(21, 90, ip="198.51.100.7", user="dana", status="SUCCESS"),
        ),
        (alert(1, "brute_force", range(1, 7)), alert(2, "sudo_after_login", [7, 8])),
        {**policy("brute_force"), **policy("sudo_after_login")},
        (
            group("brute_force", "source_ip", "203.0.113.50", range(1, 7), [1]),
            group("sudo_after_login", "source_ip", "203.0.113.50", [7, 8], [2]),
        ),
        # Rule-scoped partitioning: different rules never merge; benign events never join.
        ((1, 7), (6, 8), (1, 20), (8, 21)),
    ))
    add(CorrelationFixture(
        "ipv6_spelling_variants_group_together", "positive",
        "Two spellings of the same IPv6 address are the same entity.",
        "60s apart, inside the 300s window.",
        (ev(1, 0, ip="2001:0db8::1"), ev(2, 60, ip="2001:db8::1")),
        (alert(1, "port_scan", [1, 2]),),
        policy("port_scan"),
        (group("port_scan", "source_ip", "2001:db8::1", [1, 2], [1]),),
    ))
    add(CorrelationFixture(
        "timezone_offsets_normalize_to_utc", "positive",
        "01:00+01:00 is 00:00Z, so it is 60s from 00:01:00Z, not 1h60s.",
        "Offsets are converted to UTC before windowing.",
        (
            ev(1, timestamp="2026-10-02T01:00:00+01:00"),
            ev(2, timestamp="2026-10-02T00:01:00Z"),
        ),
        (alert(1, "brute_force", [1, 2]),),
        policy("brute_force"),
        (group("brute_force", "source_ip", "192.0.2.10", [1, 2], [1]),),
    ))
    add(CorrelationFixture(
        "cross_upload_enabled_merges_batches", "positive",
        "With cross_upload=True the same IP in two upload batches is one group.",
        "10s apart, inside the 300s window; scope is policy-wide.",
        (ev(1, 0, upload="batch-a"), ev(2, 10, upload="batch-b")),
        (alert(1, "brute_force", [1, 2]),),
        policy("brute_force", cross_upload=True),
        (group("brute_force", "source_ip", "192.0.2.10", [1, 2], [1]),),
    ))

    # ---- negative: activity that must NOT correlate -------------------------------
    add(CorrelationFixture(
        "normal_activity_without_alert", "negative",
        "Benign logins with no alert produce no correlation groups at all.",
        "Not applicable: correlation only considers events referenced by an alert.",
        tuple(ev(i, i * 30, ip=f"198.51.100.{i}", user=f"user{i}", status="SUCCESS") for i in range(1, 6)),
        (),
        policy("brute_force"),
        (),
    ))
    add(CorrelationFixture(
        "different_entities_same_time", "negative",
        "Two IPs active in the same second under one alert are not merged.",
        "Identical timestamps do not link different entities.",
        (ev(1, 0, ip="192.0.2.31"), ev(2, 0, ip="192.0.2.32")),
        (alert(1, "brute_force", [1, 2]),),
        policy("brute_force"),
        (
            group("brute_force", "source_ip", "192.0.2.31", [1], [1]),
            group("brute_force", "source_ip", "192.0.2.32", [2], [1]),
        ),
        ((1, 2),),
    ))
    add(CorrelationFixture(
        "same_user_on_different_hosts_host_policy", "negative",
        "One user on two hosts is not grouped when the rule's entity is the host.",
        "Events are 30s apart but the host differs, so entity scope wins over time.",
        (ev(1, 0, user="alice", host="host-a"), ev(2, 30, user="alice", host="host-b")),
        (alert(1, "log_tampering", [1, 2]),),
        policy("log_tampering", "host"),
        (
            group("log_tampering", "host", "host-a", [1], [1]),
            group("log_tampering", "host", "host-b", [2], [1]),
        ),
        ((1, 2),),
    ))
    add(CorrelationFixture(
        "cross_upload_default_keeps_batches_separate", "negative",
        "By default the same IP in two upload batches is not merged.",
        "10s apart, but batches are separate scopes unless cross_upload is set.",
        (ev(1, 0, upload="batch-a"), ev(2, 10, upload="batch-b")),
        (alert(1, "brute_force", [1, 2]),),
        policy("brute_force"),
        (
            group("brute_force", "source_ip", "192.0.2.10", [1], [1]),
            group("brute_force", "source_ip", "192.0.2.10", [2], [1]),
        ),
        ((1, 2),),
    ))
    add(CorrelationFixture(
        "minimum_events_not_met", "negative",
        "A policy requiring 3 events emits nothing for a 2-event cluster.",
        "Events are in the window but below minimum_events=3.",
        (ev(1, 0), ev(2, 30)),
        (alert(1, "brute_force", [1, 2]),),
        policy("brute_force", minimum_events=3),
        (),
    ))
    add(CorrelationFixture(
        "unknown_or_invalid_entities_are_skipped", "negative",
        "Unknown, missing, or malformed IPs and unparseable timestamps are never guessed at.",
        "Only event 1 has both a valid entity and a valid timestamp.",
        (
            ev(1, 0),
            ev(2, 10, ip="unknown"),
            ev(3, 20, ip=None),
            ev(4, 30, ip="999.1.1.1"),
            ev(5, timestamp="not-a-timestamp"),
        ),
        (alert(1, "brute_force", [1, 2, 3, 4, 5]),),
        policy("brute_force"),
        (group("brute_force", "source_ip", "192.0.2.10", [1], [1]),),
    ))
    add(CorrelationFixture(
        "account_names_are_case_sensitive", "negative",
        "Alice and alice are different accounts today. NOTE FOR REVIEW: if the team decides "
        "usernames should be case-insensitive, this fixture documents the change needed.",
        "30s apart; entity differs by case only.",
        (ev(1, 0, user="Alice"), ev(2, 30, user="alice")),
        (alert(1, "multi_ip_login", [1, 2]),),
        policy("multi_ip_login", "account"),
        (
            group("multi_ip_login", "account", "Alice", [1], [1]),
            group("multi_ip_login", "account", "alice", [2], [1]),
        ),
        ((1, 2),),
    ))
    add(CorrelationFixture(
        "event_not_cited_by_alert_stays_out", "negative",
        "A same-IP event inside the window that the alert does not cite is not pulled in.",
        "Event 2 is 30s from event 1 but is not alert evidence.",
        (ev(1, 0), ev(2, 30)),
        (alert(1, "brute_force", [1]),),
        policy("brute_force"),
        (group("brute_force", "source_ip", "192.0.2.10", [1], [1]),),
        ((1, 2),),
    ))

    # ---- duplicate: repeated references must not create repeated evidence ---------
    add(CorrelationFixture(
        "duplicate_event_references_collapse", "duplicate",
        "Event 1 is listed twice in the input and cited twice by one alert and once by "
        "another: one group, one evidence link per event, both alerts attached.",
        "All events within 100s of the first; window is 300s.",
        (ev(1, 0), ev(1, 0), ev(2, 50), ev(3, 100)),
        (alert(1, "brute_force", [1, 1, 2]), alert(2, "brute_force", [2, 3])),
        policy("brute_force"),
        (group("brute_force", "source_ip", "192.0.2.10", [1, 2, 3], [1, 2]),),
    ))

    # ---- boundary: exact time-window edges ----------------------------------------
    add(CorrelationFixture(
        "boundary_exactly_window_seconds_is_inclusive", "boundary",
        "An event exactly window_seconds after the first still joins the group.",
        "Gap is exactly 300s with a 300s window: inclusive, so one group.",
        (ev(1, 0), ev(2, WINDOW)),
        (alert(1, "brute_force", [1, 2]),),
        policy("brute_force"),
        (group("brute_force", "source_ip", "192.0.2.10", [1, 2], [1]),),
    ))
    add(CorrelationFixture(
        "boundary_one_second_past_window_splits", "boundary",
        "An event one second past the window starts a new group.",
        "Gap is 301s with a 300s window: exclusive of anything past the edge.",
        (ev(1, 0), ev(2, WINDOW + 1)),
        (alert(1, "brute_force", [1, 2]),),
        policy("brute_force"),
        (
            group("brute_force", "source_ip", "192.0.2.10", [1], [1]),
            group("brute_force", "source_ip", "192.0.2.10", [2], [1]),
        ),
        ((1, 2),),
    ))
    add(CorrelationFixture(
        "same_ip_outside_window", "boundary",
        "Same IP, far outside the window: separate groups.",
        "Gap is 400s against a 300s window.",
        (ev(1, 0), ev(2, 400)),
        (alert(1, "brute_force", [1, 2]),),
        policy("brute_force"),
        (
            group("brute_force", "source_ip", "192.0.2.10", [1], [1]),
            group("brute_force", "source_ip", "192.0.2.10", [2], [1]),
        ),
        ((1, 2),),
    ))
    add(CorrelationFixture(
        "boundary_window_is_anchored_not_chained", "boundary",
        "Events 200s apart would chain into one long group if windows drifted; anchored "
        "windows split them once the span from the FIRST event exceeds the window.",
        "0s/200s share a window anchored at 0s; 400s exceeds it (400>300) and re-anchors, "
        "so 400s/550s form the next. Event 2 -> 3 is only 200s apart yet stays split.",
        (ev(1, 0), ev(2, 200), ev(3, 400), ev(4, 550)),
        (alert(1, "brute_force", [1, 2, 3, 4]),),
        policy("brute_force"),
        (
            group("brute_force", "source_ip", "192.0.2.10", [1, 2], [1]),
            group("brute_force", "source_ip", "192.0.2.10", [3, 4], [1]),
        ),
        ((2, 3), (1, 4)),
    ))
    return tuple(fixtures)


FIXTURES: tuple[CorrelationFixture, ...] = _build()
