"""
Optional offline IP geolocation for identity rules.

Geo context comes from one of two places, in priority order:

1. The log source itself — many SIEM/IdP exports already carry country/ASN/
   coordinates, and app/detection/normalize.py maps those columns directly.
2. A local MaxMind-format database (GeoLite2-City / GeoLite2-ASN or any
   compatible .mmdb), configured with GEOIP_CITY_DB_PATH / GEOIP_ASN_DB_PATH.

No network lookup is ever made: sending every login IP to a third-party API
would leak user activity and add latency to every upload. With neither
source available, geo-based rules simply have nothing to evaluate.
"""

from __future__ import annotations

import logging
from functools import lru_cache
from ipaddress import ip_address
from pathlib import Path
from typing import Any, Protocol

from app.detection.models import LogRecord

logger = logging.getLogger(__name__)


class GeoResolver(Protocol):
    def lookup(self, ip: str) -> dict[str, Any] | None: ...


def is_public_ip(value: str | None) -> bool:
    if not value:
        return False
    try:
        return ip_address(value).is_global
    except ValueError:
        return False


class MaxMindResolver:
    def __init__(self, city_db_path: str | None, asn_db_path: str | None):
        import maxminddb  # imported lazily: only needed when a DB is configured

        self._city = maxminddb.open_database(city_db_path) if city_db_path else None
        self._asn = maxminddb.open_database(asn_db_path) if asn_db_path else None

    def lookup(self, ip: str) -> dict[str, Any] | None:
        result: dict[str, Any] = {}
        if self._city is not None:
            city = self._city.get(ip) or {}
            country = (city.get("country") or city.get("registered_country") or {}).get("iso_code")
            location = city.get("location") or {}
            if country:
                result["country"] = country
            if location.get("latitude") is not None and location.get("longitude") is not None:
                result["latitude"] = float(location["latitude"])
                result["longitude"] = float(location["longitude"])
        if self._asn is not None:
            asn = (self._asn.get(ip) or {}).get("autonomous_system_number")
            if asn:
                result["asn"] = str(asn)
        return result or None


@lru_cache
def _configured_resolver(city_db_path: str | None, asn_db_path: str | None) -> GeoResolver | None:
    paths = [path for path in (city_db_path, asn_db_path) if path]
    if not paths:
        return None
    missing = [path for path in paths if not Path(path).is_file()]
    if missing:
        logger.warning("GeoIP database not found, geo enrichment disabled: %s", ", ".join(missing))
        return None
    try:
        return MaxMindResolver(city_db_path, asn_db_path)
    except Exception:  # noqa: BLE001 - a bad DB file must not break uploads
        logger.exception("GeoIP database could not be opened; geo enrichment disabled")
        return None


def get_geo_resolver() -> GeoResolver | None:
    from app.core.config import settings

    return _configured_resolver(settings.geoip_city_db_path, settings.geoip_asn_db_path)


def enrich_records(records: list[LogRecord], resolver: GeoResolver | None) -> list[LogRecord]:
    """Fill missing geo fields for public source IPs. Log-supplied values win."""

    if resolver is None:
        return records
    cache: dict[str, dict | None] = {}
    enriched: list[LogRecord] = []
    for record in records:
        needs_geo = record.country is None or record.asn is None or record.latitude is None
        if not needs_geo or not is_public_ip(record.ip_address):
            enriched.append(record)
            continue
        if record.ip_address not in cache:
            cache[record.ip_address] = resolver.lookup(record.ip_address)
        geo = cache[record.ip_address] or {}
        updates = {key: value for key, value in geo.items() if getattr(record, key) is None}
        enriched.append(record.model_copy(update=updates) if updates else record)
    return enriched
