"""
Map one parser entry onto the detection engine's LogRecord.

Parsers disagree on field names: syslog/auditd emit our own names, CSV
passes columns through verbatim, JSON keeps the whole original object under
`json` (often ECS-style dotted/nested keys), and the generic parser collects
`key=value` pairs. Each LogRecord field lists the aliases it accepts, checked
in order; the first non-empty value wins. Values that don't validate (a
malformed IP, a non-numeric byte count) are dropped rather than failing the
whole upload.
"""

from __future__ import annotations

from ipaddress import ip_address as parse_ip
from typing import Any

from app.detection.models import LogRecord
from app.repositories.log_repository import port_from_parsed_data

_ALIASES: dict[str, tuple[str, ...]] = {
    "hostname": ("hostname", "host", "host.name", "host.hostname", "computer", "computer_name", "device_name", "node"),
    "process": ("process", "process.name", "program", "app_name"),
    "command": ("command", "cmdline", "command_line", "process.command_line", "process.args"),
    "file_path": ("file_path", "file.path", "target_filename", "filename", "file_name"),
    "dest_ip": (
        "dest_ip", "destination_ip", "dst_ip", "dst", "dest", "destination",
        "destination.ip", "server.ip", "id.resp_h", "remote_address",
    ),
    "protocol": ("protocol", "proto", "network.transport", "transport"),
    "bytes_out": (
        "bytes_out", "bytes_sent", "sent_bytes", "out_bytes", "orig_bytes",
        "source.bytes", "client.bytes", "upload_bytes", "tx_bytes",
    ),
    "bytes_in": (
        "bytes_in", "bytes_received", "received_bytes", "in_bytes", "resp_bytes",
        "destination.bytes", "server.bytes", "download_bytes", "rx_bytes",
    ),
    "domain": (
        "domain", "dest_domain", "destination.domain", "url.domain", "http.host",
        "server_name", "sni", "tls.server_name", "url_host",
    ),
    "dns_query": ("dns_query", "query", "qname", "query_name", "dns.question.name", "dns.qname", "question"),
    "dns_query_type": ("dns_query_type", "qtype", "qtype_name", "query_type", "dns.question.type", "record_type"),
    "country": (
        "country", "country_code", "src_country", "source_country", "geo_country",
        "source.geo.country_iso_code", "client.geo.country_iso_code", "geoip.country_code",
        "geo.country_iso_code", "geo.country",
    ),
    "asn": (
        "asn", "as_number", "src_asn", "source_asn", "source.as.number",
        "client.as.number", "geoip.asn", "geo.asn",
    ),
    "latitude": (
        "latitude", "lat", "src_lat", "source_lat", "source.geo.location.lat",
        "client.geo.location.lat", "geoip.latitude", "geo.location.lat",
    ),
    "longitude": (
        "longitude", "lon", "lng", "src_lon", "source_lon", "source.geo.location.lon",
        "client.geo.location.lon", "geoip.longitude", "geo.location.lon",
    ),
    "audit_type": ("audit_type",),
    "audit_event_id": ("audit_event_id",),
    "audit_key": ("audit_key",),
}

_INT_FIELDS = {"bytes_out", "bytes_in"}
_FLOAT_FIELDS = {"latitude", "longitude"}
_IP_FIELDS = {"dest_ip"}
# Carried into LogRecord.extra so rules can reach source-specific detail.
_EXTRA_KEYS = (
    "audit_fields", "audit_paths", "firewall_action", "source_port", "packet_length",
    "action", "direction", "url", "path",
)


def _nested(source: Any, dotted: str) -> Any:
    if not isinstance(source, dict):
        return None
    if dotted in source:
        return source[dotted]
    value: Any = source
    for part in dotted.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def _lookup(sources: list[dict], aliases: tuple[str, ...]) -> Any:
    for alias in aliases:
        for source in sources:
            value = _nested(source, alias)
            if value in (None, "", "-") or isinstance(value, (dict, list)):
                continue
            return value
    return None


def _coerce(field: str, value: Any) -> Any:
    try:
        if field in _INT_FIELDS:
            number = int(float(str(value).replace(",", "")))
            return number if number >= 0 else None
        if field in _FLOAT_FIELDS:
            return float(value)
        if field in _IP_FIELDS:
            return str(parse_ip(str(value).strip()))
    except (TypeError, ValueError):
        return None
    text = str(value).strip()
    return text or None


def log_record_from_entry(entry: dict, source_format: str | None = None) -> LogRecord:
    parsed = entry.get("parsed") or {}
    sources = [parsed]
    for nested_key in ("json", "key_values"):
        if isinstance(parsed.get(nested_key), dict):
            sources.append(parsed[nested_key])

    values: dict[str, Any] = {}
    for field, aliases in _ALIASES.items():
        # Apache's `path` is a URL path, and `host` there isn't a log host.
        if source_format == "apache_combined" and field in ("file_path", "hostname"):
            continue
        raw = _lookup(sources, aliases)
        if raw is not None:
            coerced = _coerce(field, raw)
            if coerced is not None:
                values[field] = coerced

    # Out-of-range geo coordinates would fail LogRecord validation.
    if not -90 <= values.get("latitude", 0) <= 90 or not -180 <= values.get("longitude", 0) <= 180:
        values.pop("latitude", None)
        values.pop("longitude", None)

    for lowercase in ("dns_query", "domain"):
        if values.get(lowercase):
            values[lowercase] = values[lowercase].rstrip(".").lower()
    if values.get("country"):
        values["country"] = values["country"].upper() if len(values["country"]) <= 3 else values["country"]
    if values.get("asn"):
        values["asn"] = values["asn"].upper().removeprefix("AS")

    extra = {key: parsed[key] for key in _EXTRA_KEYS if key in parsed and parsed[key] not in (None, "")}

    return LogRecord(
        line_number=entry["line_number"],
        timestamp=parsed.get("timestamp"),
        ip_address=parsed.get("ip_address") or None,
        username=parsed.get("username") or None,
        event_type=parsed.get("event_type"),
        status=parsed.get("status"),
        port=port_from_parsed_data(parsed) or port_from_parsed_data(_flatten_port_sources(sources[1:])),
        message=parsed.get("message") or None,
        extra=extra,
        **values,
    )


def _flatten_port_sources(sources: list[dict]) -> dict:
    merged: dict = {}
    for source in sources:
        for key in ("destination_port", "dest_port", "dport", "server_port", "port", "id.resp_p"):
            value = _nested(source, key) if key != "id.resp_p" else source.get(key)
            if value not in (None, "") and key not in merged:
                merged["destination_port" if key == "id.resp_p" else key] = value
        destination = source.get("destination")
        if isinstance(destination, dict) and destination.get("port") is not None:
            merged.setdefault("destination_port", destination["port"])
    return merged
