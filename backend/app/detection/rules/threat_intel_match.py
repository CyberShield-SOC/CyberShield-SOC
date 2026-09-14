from __future__ import annotations

from app.detection._ts import parse_ts, ts_to_str
from app.detection.models import Alert, LogRecord
from app.detection.rules._host_alerts import endpoint_id
from app.detection.rules.base import BaseRule


class ThreatIntelMatchRule(BaseRule):
    """Fires when an event's source IP, destination IP, domain, or DNS query
    matches an indicator from an imported threat-intelligence feed.

    Feeds are managed through /threat-intel/feeds (no provider is built in),
    so this needs a database session and at least one imported feed; with
    neither it produces nothing. Matches are grouped per (internal entity,
    indicator) within one upload so a chatty connection yields one alert.
    `allowlist` suppresses specific indicators (e.g. a false-positive IP).
    """

    name = "threat_intel_match"
    description = "Traffic or DNS activity matched an imported threat-intelligence indicator."
    severity = "HIGH"
    mitre_technique = "T1071"
    entity_type = "host"
    confidence = 85

    def __init__(self, cooldown_seconds: int = 3600, allowlist: list[str] | None = None):
        self.cooldown_seconds = cooldown_seconds
        self.allowlist = allowlist
        self._suppressed = {item.strip().lower() for item in (allowlist or ())}

    def _matcher(self, db):
        from app.repositories.threat_intel_repository import load_matcher

        return load_matcher(db)

    def analyze(self, records: list[LogRecord], db=None) -> list[Alert]:
        if db is None:
            return []
        matcher = self._matcher(db)
        if not matcher:
            return []

        groups: dict[tuple[str, str, str], dict] = {}
        for record in records:
            hits: list[tuple[str, str, str, str]] = []  # (indicator, feed, observed, direction)
            source_hit = matcher.match_ip(record.ip_address)
            if source_hit:
                hits.append((*source_hit, record.ip_address, "inbound"))
            dest_hit = matcher.match_ip(record.dest_ip)
            if dest_hit:
                hits.append((*dest_hit, record.dest_ip, "outbound"))
            for observed in (record.domain, record.dns_query):
                domain_hit = matcher.match_domain(observed)
                if domain_hit:
                    hits.append((*domain_hit, observed, "dns" if observed == record.dns_query else "outbound"))
                    break

            for indicator, feed, observed, direction in hits:
                if indicator.lower() in self._suppressed or (observed or "").lower() in self._suppressed:
                    continue
                # The pivot is always our side of the conversation.
                entity_type = "host"
                own_ip = record.dest_ip if direction == "inbound" else record.ip_address
                entity = endpoint_id(record, own_ip) or "unknown-host"
                key = (entity, indicator, direction)
                group = groups.setdefault(key, {
                    "records": [], "feed": feed, "observed": set(), "entity_type": entity_type,
                })
                group["records"].append(record)
                group["observed"].add(observed)

        alerts: list[Alert] = []
        for (entity, indicator, direction), group in groups.items():
            recs = group["records"]
            stamps = sorted(ts for ts in (parse_ts(r.timestamp) for r in recs) if ts is not None)
            sample = recs[0]
            peer = {
                "inbound": f"from {indicator}",
                "outbound": f"to {indicator}",
                "dns": f"resolving {', '.join(sorted(group['observed']))}",
            }[direction]
            alerts.append(Alert(
                rule=self.name,
                severity=self.severity,
                source_ip=sample.ip_address,
                username=sample.username,
                hostname=sample.hostname,
                count=len(recs),
                time_window_seconds=int((stamps[-1] - stamps[0]).total_seconds()) if len(stamps) > 1 else 0,
                first_seen=ts_to_str(stamps[0]) if stamps else sample.timestamp,
                last_seen=ts_to_str(stamps[-1]) if stamps else sample.timestamp,
                description=(
                    f"{entity} had {len(recs)} event(s) {peer}, listed in threat feed '{group['feed']}'."
                ),
                matched_line_numbers=sorted({r.line_number for r in recs}),
                mitre_technique=self.mitre_technique,
                confidence=self.confidence,
                entity_type=group["entity_type"],
                entity_id=entity,
                evidence={
                    "indicator": indicator,
                    "feed": group["feed"],
                    "direction": direction,
                    "observed": sorted(group["observed"])[:10],
                    "destination_port": sample.port,
                },
            ))
        return alerts
