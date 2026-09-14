from __future__ import annotations

from app.detection._ts import parse_ts, ts_to_str
from app.detection.models import Alert
from app.detection.rules.base import BaseRule


def host_alert(
    rule: BaseRule,
    *,
    hostname: str | None,
    timestamp: str | None,
    line_numbers: list[int],
    prefix: str,
    reason: str,
    username: str | None = None,
    source_ip: str | None = None,
    evidence: dict | None = None,
) -> Alert:
    """One single-event, host-pivoted finding (Group A rules)."""

    ts = parse_ts(timestamp)
    seen = ts_to_str(ts) if ts else timestamp
    host = hostname or "unknown-host"
    return Alert(
        rule=rule.name,
        severity=rule.severity,
        hostname=hostname,
        username=username,
        source_ip=source_ip,
        count=1,
        time_window_seconds=0,
        first_seen=seen,
        last_seen=seen,
        description=f"{prefix} on {host}: {reason}.",
        matched_line_numbers=sorted(set(line_numbers)),
        mitre_technique=rule.mitre_technique,
        confidence=rule.confidence,
        entity_type="host",
        entity_id=host,
        evidence={"reason": reason, "prefix": prefix, **(evidence or {})},
    )


def merge_host_alerts(rule: BaseRule, alerts: list[Alert], window_seconds: int) -> list[Alert]:
    """Fold findings for the same host that fall within `window_seconds` of
    each other into one alert listing every distinct action.

    Cooldown suppression keys on (rule, host); without this, a second,
    different action on the same host (clearing history minutes after
    stopping auditd) would be silently dropped instead of reported.
    """

    window = max(int(window_seconds or 0), 0)
    by_host: dict[str, list[Alert]] = {}
    for alert in alerts:
        by_host.setdefault(alert.entity_id or "unknown-host", []).append(alert)

    merged: list[Alert] = []
    for host, host_alerts in by_host.items():
        host_alerts.sort(key=lambda a: parse_ts(a.first_seen) or parse_ts("1970-01-01T00:00:00Z"))
        group: list[Alert] = []
        for alert in host_alerts:
            if group and window:
                start = parse_ts(group[0].first_seen)
                current = parse_ts(alert.first_seen)
                if start and current and (current - start).total_seconds() > window:
                    merged.append(_combine(group))
                    group = []
            elif group and not window:
                merged.append(_combine(group))
                group = []
            group.append(alert)
        if group:
            merged.append(_combine(group))
    return merged


def _combine(group: list[Alert]) -> Alert:
    if len(group) == 1:
        alert = group[0]
        return alert.model_copy(update={"evidence": {k: v for k, v in alert.evidence.items() if k != "prefix"}})
    first, last = group[0], group[-1]
    reasons = list(dict.fromkeys(a.evidence.get("reason", a.description) for a in group))
    prefix = first.evidence.get("prefix", "Multiple findings")
    host = first.entity_id
    start, end = parse_ts(first.first_seen), parse_ts(last.last_seen)
    return first.model_copy(update={
        "count": sum(a.count for a in group),
        "last_seen": last.last_seen,
        "time_window_seconds": int((end - start).total_seconds()) if start and end else 0,
        "username": next((a.username for a in group if a.username), None),
        "description": f"{prefix} on {host} ({len(group)} actions): {'; '.join(reasons)}.",
        "matched_line_numbers": sorted({n for a in group for n in a.matched_line_numbers}),
        "evidence": {"reasons": reasons, "findings": [
            {k: v for k, v in a.evidence.items() if k != "prefix"} for a in group
        ]},
    })


def endpoint_id(record, ip: str | None) -> str | None:
    """Identify the endpoint a network event belongs to.

    Logs relayed by an appliance through syslog (firewall kernel lines, a DNS
    server's query log) carry the *appliance's* name in `hostname`, so the
    endpoint is the IP. Flow/proxy exports (CSV/JSON, no `process`) put the
    originating machine's name in their host column.
    """

    if record.process:
        return ip
    return record.hostname or ip
