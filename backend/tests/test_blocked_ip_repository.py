"""Regression coverage for the auto-block dedup fix.

At real upload volume the same source IP routinely qualifies for
auto-blocking from several different alerts in one batch (e.g. multiple
password_spraying windows against different usernames). The old
select-then-insert create_or_update_blocked_ip() had no way to see an
uncommitted duplicate from earlier in the same loop, so Postgres raised a
UniqueViolation on the batched flush the moment two qualifying alerts shared
an IP — reproduced with a 400k-line synthetic upload before this fix.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from app.repositories.blocked_ip_repository import auto_block_from_alerts

pytestmark = pytest.mark.no_db


def alert(rule, source_ip, description="qualifying alert"):
    return SimpleNamespace(rule=rule, source_ip=source_ip, description=description)


def test_same_ip_across_multiple_qualifying_alerts_is_deduplicated():
    alerts = [
        alert("password_spraying", "203.0.113.9", "first window"),
        alert("password_spraying", "203.0.113.9", "second window"),
        alert("port_scan", "203.0.113.9", "third window"),
    ]

    with patch(
        "app.repositories.blocked_ip_repository.bulk_create_or_update_blocked_ips",
        return_value=[MagicMock()],
    ) as bulk_upsert:
        db = MagicMock()
        summary = auto_block_from_alerts(db, alerts)

    bulk_upsert.assert_called_once()
    rows = bulk_upsert.call_args.args[1]
    assert len(rows) == 1
    assert rows[0]["ip"] == "203.0.113.9"
    # Last-matching-alert-wins, same as the original per-alert loop.
    assert rows[0]["rule_name"] == "port_scan"
    assert rows[0]["reason"] == "third window"
    assert summary["qualifying_alerts"] == 3
    assert summary["unique_addresses"] == 1
    assert summary["blocked_addresses"] == 1


def test_distinct_ips_are_not_merged():
    alerts = [
        alert("password_spraying", "203.0.113.9"),
        alert("port_scan", "198.51.100.4"),
    ]

    with patch(
        "app.repositories.blocked_ip_repository.bulk_create_or_update_blocked_ips",
        return_value=[MagicMock(), MagicMock()],
    ) as bulk_upsert:
        db = MagicMock()
        auto_block_from_alerts(db, alerts)

    rows = bulk_upsert.call_args.args[1]
    assert {row["ip"] for row in rows} == {"203.0.113.9", "198.51.100.4"}


def test_alerts_without_source_ip_or_non_qualifying_rule_are_skipped():
    alerts = [
        alert("password_spraying", None),
        alert("brute_force_login", "203.0.113.9"),  # not in AUTO_BLOCK_RULES
    ]

    with patch(
        "app.repositories.blocked_ip_repository.bulk_create_or_update_blocked_ips",
        return_value=[],
    ) as bulk_upsert:
        db = MagicMock()
        summary = auto_block_from_alerts(db, alerts)

    assert bulk_upsert.call_args.args[1] == []
    assert summary["qualifying_alerts"] == 0
    assert summary["unique_addresses"] == 1


def test_bulk_upsert_returns_empty_without_a_query_for_no_rows():
    from app.repositories.blocked_ip_repository import bulk_create_or_update_blocked_ips

    db = MagicMock()
    assert bulk_create_or_update_blocked_ips(db, []) == []
    db.execute.assert_not_called()
