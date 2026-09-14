from __future__ import annotations

import math
from collections import Counter, defaultdict, deque

from app.detection._ts import parse_ts, ts_to_str
from app.detection.models import Alert, LogRecord
from app.detection.rules.base import BaseRule

# Two-label public suffixes common enough that "last two labels" would pick
# the suffix itself as the parent domain. Not a full public-suffix list.
_MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz", "co.jp",
    "com.br", "com.cn", "co.in", "co.za", "com.mx", "com.tr", "co.kr", "com.sg", "com.hk",
}


def parent_domain(name: str) -> tuple[str, str]:
    """Split a query into (subdomain part, registrable parent domain)."""

    labels = name.lower().rstrip(".").split(".")
    take = 3 if len(labels) >= 3 and ".".join(labels[-2:]) in _MULTI_LABEL_SUFFIXES else 2
    if len(labels) <= take:
        return "", ".".join(labels)
    return ".".join(labels[:-take]), ".".join(labels[-take:])


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


class DnsTunnelingRule(BaseRule):
    """Fires when one client sends many long, high-entropy queries under a
    single parent domain within window_seconds — data smuggled in DNS labels.

    A query is suspicious when its subdomain part (dots removed) is at least
    params.min_subdomain_length characters with Shannon entropy >=
    params.min_entropy bits/char. The rule fires when >= threshold distinct
    suspicious queries hit one parent domain in the window. Needs DNS query
    logs: dnsmasq/BIND/Unbound via syslog, or CSV/JSON with a query-name
    column. CDNs and security products that legitimately use hashed
    subdomains belong in `allowlist` (parent domains).
    """

    name = "dns_tunneling"
    description = "A client sent many long, high-entropy DNS queries to one parent domain."
    severity = "HIGH"
    mitre_technique = "T1071.004"
    entity_type = "source_ip"
    confidence = 70
    DEFAULT_PARAMS = {"min_subdomain_length": 30, "min_entropy": 3.5}

    def __init__(
        self,
        threshold: int = 20,
        window_seconds: int = 600,
        cooldown_seconds: int = 3600,
        allowlist: list[str] | None = None,
        params: dict | None = None,
    ):
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.cooldown_seconds = cooldown_seconds
        self.allowlist = allowlist
        self.params = self.merge_params(params)
        self._allowed = {item.strip().lower().rstrip(".") for item in (allowlist or ())}

    def analyze(self, records: list[LogRecord], db=None) -> list[Alert]:
        min_length = int(self.params["min_subdomain_length"])
        min_entropy = float(self.params["min_entropy"])
        groups: dict[tuple[str, str], list] = defaultdict(list)

        for record in records:
            client = record.ip_address or record.hostname
            if not record.dns_query or not client:
                continue
            subdomain, parent = parent_domain(record.dns_query)
            if parent in self._allowed:
                continue
            compact = subdomain.replace(".", "")
            if len(compact) < min_length:
                continue
            entropy = shannon_entropy(compact)
            if entropy < min_entropy:
                continue
            ts = parse_ts(record.timestamp)
            if ts is not None:
                groups[(client, parent)].append((ts, record, len(compact), entropy))

        alerts: list[Alert] = []
        for (client, parent), events in groups.items():
            events.sort(key=lambda item: item[0])
            window: deque = deque()
            for event in events:
                window.append(event)
                while (event[0] - window[0][0]).total_seconds() > self.window_seconds:
                    window.popleft()
                distinct = {item[1].dns_query for item in window}
                if len(distinct) < self.threshold:
                    continue
                matched = list(window)
                avg_length = sum(item[2] for item in matched) / len(matched)
                avg_entropy = sum(item[3] for item in matched) / len(matched)
                qtypes = Counter((item[1].dns_query_type or "UNKNOWN") for item in matched)
                alerts.append(Alert(
                    rule=self.name,
                    severity=self.severity,
                    source_ip=matched[0][1].ip_address,
                    hostname=matched[0][1].hostname,
                    count=len(matched),
                    time_window_seconds=self.window_seconds,
                    first_seen=ts_to_str(matched[0][0]),
                    last_seen=ts_to_str(event[0]),
                    description=(
                        f"Possible DNS tunneling from {client}: {len(distinct)} long high-entropy "
                        f"queries under {parent} within {self.window_seconds}s "
                        f"(avg {avg_length:.0f} chars, {avg_entropy:.2f} bits/char)."
                    ),
                    matched_line_numbers=[item[1].line_number for item in matched],
                    mitre_technique=self.mitre_technique,
                    confidence=self.confidence,
                    entity_type=self.entity_type,
                    entity_id=client,
                    evidence={
                        "parent_domain": parent,
                        "distinct_queries": len(distinct),
                        "avg_subdomain_length": round(avg_length, 1),
                        "avg_entropy": round(avg_entropy, 2),
                        "query_types": dict(qtypes),
                        "sample_queries": sorted(distinct)[:3],
                    },
                ))
                window.clear()
        return alerts
