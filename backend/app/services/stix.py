"""STIX 2.1 for threat-intelligence feeds.

Import reads the network indicators a blocklist can act on (IPv4/IPv6
addresses and ranges, domain names) out of the ``indicator`` objects in a
bundle. Export writes a feed back out as a bundle of indicators. No STIX
library is involved: this subset is a small, fixed shape.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from ipaddress import ip_address
from uuid import UUID, uuid5

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.threat_indicator import ThreatIndicator

STIX_MEDIA_TYPE = "application/stix+json;version=2.1"

# Ids are derived (UUIDv5) from the feed name and the indicator, so exporting
# the same feed twice yields the same objects and a consumer can de-duplicate.
_NAMESPACE = UUID("6f2c1b0e-6a0b-5d0c-9c57-4a6f0b7f2d11")

# [ipv4-addr:value = '198.51.100.7'], ISSUBSET for ranges; several
# comparisons may be joined with OR inside one pattern.
_COMPARISON = re.compile(
    r"\b(ipv4-addr|ipv6-addr|domain-name):value\s*(?:=|ISSUBSET)\s*'((?:[^'\\]|\\.)*)'",
    re.IGNORECASE,
)


class StixError(ValueError):
    """The content is JSON but not a usable STIX 2.1 bundle."""


def looks_like_json(content: str) -> bool:
    return content.lstrip("﻿ \t\r\n").startswith("{")


def _stix_time(value: datetime | None) -> str:
    value = value or datetime.now(timezone.utc)
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{value.microsecond // 1000:03d}Z"


def _expired(valid_until, now: datetime) -> bool:
    if not isinstance(valid_until, str):
        return False
    try:
        until = datetime.fromisoformat(valid_until.replace("Z", "+00:00"))
    except ValueError:
        return False
    if until.tzinfo is None:
        until = until.replace(tzinfo=timezone.utc)
    return until <= now


def parse_stix_bundle(content: str, *, now: datetime | None = None) -> tuple[list[str], int]:
    """Return (indicator values, rejected indicator count) from a bundle.

    An indicator is rejected when it is revoked, past ``valid_until``, not a
    STIX pattern, or holds nothing but observable types this platform cannot
    match (file hashes, URLs, e-mail addresses). Objects that are not
    indicators (identities, malware, relationships) are context, not
    rejections.
    """

    try:
        bundle = json.loads(content.lstrip("﻿"))
    except (json.JSONDecodeError, RecursionError) as exc:
        raise StixError("The feed looks like JSON but could not be read.") from exc
    if not isinstance(bundle, dict) or bundle.get("type") != "bundle" or not isinstance(bundle.get("objects"), list):
        raise StixError("JSON feeds must be a STIX 2.1 bundle with an objects list.")

    now = now or datetime.now(timezone.utc)
    values: list[str] = []
    rejected = 0
    for item in bundle["objects"]:
        if not isinstance(item, dict) or item.get("type") != "indicator":
            continue
        pattern = item.get("pattern")
        usable = (
            isinstance(pattern, str)
            and item.get("pattern_type", "stix") == "stix"
            and item.get("revoked") is not True
            and not _expired(item.get("valid_until"), now)
        )
        found = [
            re.sub(r"\\(.)", r"\1", match.group(2)) for match in _COMPARISON.finditer(pattern)
        ] if usable else []
        if not found:
            rejected += 1
            continue
        values.extend(found)
    return values, rejected


def _pattern(indicator: str, indicator_type: str) -> str:
    if indicator_type == "domain":
        observable = "domain-name"
    else:
        address = indicator.split("/", 1)[0]
        observable = "ipv6-addr" if ip_address(address).version == 6 else "ipv4-addr"
    escaped = indicator.replace("\\", "\\\\").replace("'", "\\'")
    return f"[{observable}:value = '{escaped}']"


def export_stix_bundle(db: Session, source: str) -> dict | None:
    """One feed as a STIX 2.1 bundle, or None when the feed does not exist."""

    rows = db.scalars(
        select(ThreatIndicator)
        .where(ThreatIndicator.source == source)
        .order_by(ThreatIndicator.indicator)
    ).all()
    if not rows:
        return None

    identity_id = f"identity--{uuid5(_NAMESPACE, 'identity:cybershield-soc')}"
    first_seen = _stix_time(min(row.created_at for row in rows))
    objects: list[dict] = [{
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": first_seen,
        "modified": first_seen,
        "name": "CyberShield SOC",
        "identity_class": "system",
    }]
    for row in rows:
        created = _stix_time(row.created_at)
        indicator = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid5(_NAMESPACE, f'{source}|{row.indicator}')}",
            "created_by_ref": identity_id,
            "created": created,
            "modified": created,
            "name": f"{source}: {row.indicator}",
            "indicator_types": ["malicious-activity"],
            "pattern": _pattern(row.indicator, row.indicator_type),
            "pattern_type": "stix",
            "valid_from": created,
            "labels": [source],
        }
        if row.description:
            indicator["description"] = row.description
        objects.append(indicator)

    return {
        "type": "bundle",
        "id": f"bundle--{uuid5(_NAMESPACE, f'bundle:{source}')}",
        "objects": objects,
    }
