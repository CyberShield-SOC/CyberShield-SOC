"""
Threat-intelligence indicator storage and matching.

Feeds are plain text — one IP, CIDR range, or domain per line; `#` starts a
comment; CSV-style lines use the first column. That covers the common
blocklist exports (abuse.ch, Spamhaus DROP, FireHOL, internal IOC lists)
without tying the platform to any one provider.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from ipaddress import ip_address, ip_network

from sqlalchemy import delete, func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.models.threat_indicator import ThreatIndicator

MAX_INDICATORS_PER_IMPORT = 100_000
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_SOURCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._:-]{0,99}$")


class ThreatFeedError(ValueError):
    """Invalid feed name or content."""


def classify_indicator(raw: str) -> tuple[str, str] | None:
    """Return (normalized_indicator, type) or None if it isn't a usable indicator."""

    value = raw.strip().strip('"').strip("'")
    if not value:
        return None
    value = re.sub(r"^[a-z]+://", "", value, flags=re.IGNORECASE).split("/", 1)[0] if "://" in value else value
    try:
        return str(ip_address(value)), "ip"
    except ValueError:
        pass
    if "/" in value:
        try:
            network = ip_network(value, strict=False)
        except ValueError:
            return None
        if network.num_addresses == 1:
            return str(network.network_address), "ip"
        # Refuse absurdly broad ranges that would match most of the internet.
        if network.prefixlen < (8 if network.version == 4 else 32):
            return None
        return str(network), "cidr"
    domain = value.lower().rstrip(".")
    if domain.startswith("*."):
        domain = domain[2:]
    if _DOMAIN_RE.match(domain):
        return domain, "domain"
    return None


def parse_feed(content: str) -> tuple[list[tuple[str, str]], int]:
    """Return (unique indicators, count of rejected non-comment lines)."""

    indicators: dict[str, str] = {}
    rejected = 0
    for line in content.splitlines():
        line = line.split("#", 1)[0].split(";", 1)[0].strip()
        if not line:
            continue
        first = re.split(r"[,\t ]+", line, maxsplit=1)[0]
        classified = classify_indicator(first)
        if classified is None:
            rejected += 1
            continue
        indicators[classified[0]] = classified[1]
    return list(indicators.items()), rejected


def validate_source_name(source: str) -> str:
    source = (source or "").strip()
    if not _SOURCE_RE.match(source):
        raise ThreatFeedError("Feed name must be 1-100 letters, digits, spaces, or . _ : -")
    return source


def import_feed(
    db: Session,
    *,
    source: str,
    content: str,
    replace: bool,
    description: str | None,
    created_by: int | None,
) -> dict:
    source = validate_source_name(source)
    indicators, rejected = parse_feed(content)
    if not indicators:
        raise ThreatFeedError("The feed contained no valid IP, CIDR, or domain indicators.")
    if len(indicators) > MAX_INDICATORS_PER_IMPORT:
        raise ThreatFeedError(f"A single import is limited to {MAX_INDICATORS_PER_IMPORT} indicators.")

    removed = 0
    if replace:
        removed = db.execute(delete(ThreatIndicator).where(ThreatIndicator.source == source)).rowcount or 0

    rows = [
        {
            "source": source,
            "indicator": indicator,
            "indicator_type": indicator_type,
            "description": description,
            "created_by": created_by,
        }
        for indicator, indicator_type in indicators
    ]
    for start in range(0, len(rows), 5000):
        db.execute(
            insert(ThreatIndicator)
            .values(rows[start:start + 5000])
            .on_conflict_do_nothing(index_elements=["source", "indicator"])
        )
    db.flush()
    return {"source": source, "imported": len(indicators), "rejected_lines": rejected, "replaced": removed}


def list_feeds(db: Session) -> list[dict]:
    rows = db.execute(
        select(
            ThreatIndicator.source,
            func.count(ThreatIndicator.id),
            func.max(ThreatIndicator.created_at),
            func.count().filter(ThreatIndicator.indicator_type == "ip"),
            func.count().filter(ThreatIndicator.indicator_type == "cidr"),
            func.count().filter(ThreatIndicator.indicator_type == "domain"),
        )
        .group_by(ThreatIndicator.source)
        .order_by(ThreatIndicator.source)
    ).all()
    return [
        {
            "source": source,
            "indicator_count": total,
            "updated_at": updated.isoformat() if updated else None,
            "by_type": {"ip": ips, "cidr": cidrs, "domain": domains},
        }
        for source, total, updated, ips, cidrs, domains in rows
    ]


def list_indicators(db: Session, *, source: str | None, limit: int) -> list[dict]:
    statement = select(ThreatIndicator).order_by(ThreatIndicator.source, ThreatIndicator.indicator).limit(limit)
    if source:
        statement = statement.where(ThreatIndicator.source == source)
    return [
        {"source": row.source, "indicator": row.indicator, "type": row.indicator_type, "description": row.description}
        for row in db.scalars(statement).all()
    ]


def delete_feed(db: Session, source: str) -> int:
    return db.execute(delete(ThreatIndicator).where(ThreatIndicator.source == source)).rowcount or 0


@dataclass
class ThreatIntelMatcher:
    ips: dict[str, str] = field(default_factory=dict)
    networks: list[tuple[object, str]] = field(default_factory=list)
    domains: dict[str, str] = field(default_factory=dict)

    def __bool__(self) -> bool:
        return bool(self.ips or self.networks or self.domains)

    def match_ip(self, value: str | None) -> tuple[str, str] | None:
        if not value:
            return None
        if value in self.ips:
            return value, self.ips[value]
        try:
            address = ip_address(value)
        except ValueError:
            return None
        for network, source in self.networks:
            if address.version == network.version and address in network:
                return str(network), source
        return None

    def match_domain(self, value: str | None) -> tuple[str, str] | None:
        """Exact or parent-domain match: a listed `evil.com` matches `a.b.evil.com`."""

        if not value:
            return None
        labels = value.lower().rstrip(".").split(".")
        for start in range(len(labels) - 1):
            candidate = ".".join(labels[start:])
            if candidate in self.domains:
                return candidate, self.domains[candidate]
        return None


def load_matcher(db: Session) -> ThreatIntelMatcher:
    matcher = ThreatIntelMatcher()
    for indicator, indicator_type, source in db.execute(
        select(ThreatIndicator.indicator, ThreatIndicator.indicator_type, ThreatIndicator.source)
    ):
        if indicator_type == "ip":
            matcher.ips.setdefault(indicator, source)
        elif indicator_type == "cidr":
            matcher.networks.append((ip_network(indicator), source))
        else:
            matcher.domains.setdefault(indicator, source)
    return matcher
