from datetime import datetime, timezone

from sqlalchemy import case, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.blocked_ip import BlockedIp

AUTO_BLOCK_RULES = {
    "port_scan",
    "password_spraying",
    "credential_stuffing_success"
}


def _upsert_blocked_ips_statement(rows: list[dict]):
    """
    Build one INSERT ... ON CONFLICT (ip) DO UPDATE statement for `rows`
    (each a {"ip", "rule_name", "reason"} dict).

    Reactivate + bump block_count only when the existing row was inactive;
    leave an already-active block's count/rule/reason untouched.
    """
    stmt = pg_insert(BlockedIp).values([
        {"ip": row["ip"], "rule_name": row["rule_name"], "reason": row["reason"], "is_active": True, "block_count": 1}
        for row in rows
    ])
    return stmt.on_conflict_do_update(
        index_elements=[BlockedIp.ip],
        set_={
            "is_active": True,
            "block_count": case(
                (BlockedIp.is_active.is_(True), BlockedIp.block_count),
                else_=BlockedIp.block_count + 1,
            ),
            "rule_name": case(
                (BlockedIp.is_active.is_(True), BlockedIp.rule_name),
                else_=stmt.excluded.rule_name,
            ),
            "reason": case(
                (BlockedIp.is_active.is_(True), BlockedIp.reason),
                else_=stmt.excluded.reason,
            ),
        },
    ).returning(BlockedIp)


def bulk_create_or_update_blocked_ips(db: Session, rows: list[dict]) -> list[BlockedIp]:
    """
    Batches the upsert from `_upsert_blocked_ips_statement` for many IPs in
    one statement. `rows` must already be deduplicated by ip — Postgres
    rejects an ON CONFLICT upsert that targets the same row twice within a
    single statement's VALUES list.
    """
    if not rows:
        return []
    stmt = _upsert_blocked_ips_statement(rows)
    return list(db.execute(stmt).scalars().all())


def auto_block_from_alerts(db: Session, alerts: list[Alert]) -> dict:
    """
    Process alerts and auto-block IPs according to high severity rule configurations.
    Returns tracking info: qualifying alerts, unique IPs, and blocked IPs.
    """
    qualifying_alerts = 0
    unique_addresses = set()
    # Dedupe by IP before the upsert: the same source IP routinely qualifies
    # from multiple alerts in one upload (e.g. several password_spraying
    # windows against different usernames). Last-matching-alert-wins for
    # rule_name/reason, same as the previous per-alert loop.
    qualifying_by_ip: dict[str, dict] = {}

    for alert in alerts:
        if not alert.source_ip:
            continue

        unique_addresses.add(alert.source_ip)

        if alert.rule in AUTO_BLOCK_RULES:
            qualifying_alerts += 1
            qualifying_by_ip[alert.source_ip] = {
                "ip": alert.source_ip,
                "rule_name": alert.rule,
                "reason": alert.description,
            }

    blocked = bulk_create_or_update_blocked_ips(db, list(qualifying_by_ip.values()))
    db.flush()

    return {
        "qualifying_alerts": qualifying_alerts,
        "unique_addresses": len(unique_addresses),
        "blocked_addresses": len(blocked),
    }


def unblock_ip(db: Session, ip: str, unblock_reason: str, username: str) -> BlockedIp | None:
    stmt = select(BlockedIp).where(BlockedIp.ip == ip, BlockedIp.is_active == True)
    blocked_ip = db.execute(stmt).scalar_one_or_none()

    if blocked_ip:
        blocked_ip.is_active = False
        blocked_ip.unblock_reason = unblock_reason
        blocked_ip.unblocked_at = datetime.now(timezone.utc)
        blocked_ip.updated_by = username
        db.flush()

    return blocked_ip
