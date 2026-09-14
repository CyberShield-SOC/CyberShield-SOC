from __future__ import annotations

from typing import Any, Literal, Optional, Union

from pydantic import BaseModel, Field

EntityType = Literal["source_ip", "account", "host"]
ParamValue = Union[bool, int, float, str]


class LogRecord(BaseModel):
    """
    Normalised view of a single parsed event consumed by the detection engine.

    Built by app/detection/normalize.py from whatever a parser produced. Only
    the first block is guaranteed to be meaningful for every source; every
    other field is None unless that upload's format carries it (see the
    README's "required log sources" section). Rules must treat a missing
    field as "no data", never as a negative signal.
    """

    line_number: int
    timestamp: Optional[str] = None
    ip_address: Optional[str] = None
    username: Optional[str] = None
    event_type: Optional[str] = None
    status: Optional[str] = None
    # Destination port for network events (kept as `port` for compatibility
    # with custom rules and the persisted Log.port column).
    port: Optional[int] = Field(default=None, ge=1, le=65535)

    # Host / process context (syslog, auditd, CSV/JSON host columns).
    hostname: Optional[str] = None
    process: Optional[str] = None
    message: Optional[str] = None
    command: Optional[str] = None
    file_path: Optional[str] = None

    # Network context (firewall/netflow/proxy). ip_address is the source.
    dest_ip: Optional[str] = None
    protocol: Optional[str] = None
    bytes_out: Optional[int] = Field(default=None, ge=0)
    bytes_in: Optional[int] = Field(default=None, ge=0)
    domain: Optional[str] = None

    # DNS context.
    dns_query: Optional[str] = None
    dns_query_type: Optional[str] = None

    # Geo context for ip_address — supplied by the log source or filled in by
    # app/detection/geoip.py when a local GeoIP database is configured.
    country: Optional[str] = None
    asn: Optional[str] = None
    latitude: Optional[float] = Field(default=None, ge=-90, le=90)
    longitude: Optional[float] = Field(default=None, ge=-180, le=180)

    # Linux audit context (auditd raw logs or audit lines forwarded via syslog).
    audit_type: Optional[str] = None
    audit_event_id: Optional[str] = None
    audit_key: Optional[str] = None

    # Source-specific attributes a rule may need that don't merit a typed
    # field (audit syscall/nametype/flags, firewall action, ...).
    extra: dict[str, Any] = Field(default_factory=dict)


class Alert(BaseModel):
    """Detection result emitted by any rule — shared contract for the React dashboard."""

    rule: str
    severity: str                        # "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    source_ip: Optional[str] = None
    username: Optional[str] = None
    hostname: Optional[str] = None
    count: int
    time_window_seconds: int
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    description: str
    matched_line_numbers: list[int]
    # MITRE ATT&CK technique ID this alert corresponds to (e.g. "T1110.001").
    mitre_technique: Optional[str] = None
    # Detection-confidence, independent of severity: how sure the rule is
    # that this is really the described behavior (0-100), as opposed to how
    # bad it would be if true (severity).
    confidence: int = Field(default=70, ge=0, le=100)
    # What entity this alert's count/window/dedup apply to. entity_id is the
    # actual value (an IP, a username, or a hostname) — source_ip/username/
    # hostname above remain for display/filtering; entity_type+entity_id is
    # the generalized pivot used for cooldown suppression.
    entity_type: EntityType = "source_ip"
    entity_id: Optional[str] = None
    # Rule-specific facts an analyst needs to triage (destination, matched
    # indicator, distance/speed, byte counts, ...). Small, JSON-serialisable.
    evidence: dict[str, Any] = Field(default_factory=dict)


class RuleConfig(BaseModel):
    """Configurable Detection Engine v2 thresholds for a rule."""

    threshold: int | None = Field(default=None, ge=1)
    fail_threshold: int | None = Field(default=None, ge=1)
    window_seconds: int | None = Field(default=None, ge=1)
    success_window_seconds: int | None = Field(default=None, ge=1)
    # Suppress repeat alerts for the same (rule, entity) pair within this many
    # seconds of the most recent stored alert. None/0 disables suppression.
    cooldown_seconds: int | None = Field(default=None, ge=0)
    confidence: int | None = Field(default=None, ge=0, le=100)
    # Generic named-list config: service-account names, decommissioned
    # accounts, process allowlists, etc. — whatever one rule needs a
    # configurable roster for. Never hardcode a roster in rule code.
    allowlist: list[str] | None = None
    # Static business-hours window (inclusive start, exclusive end, 0-23) for
    # rules like off_hours_login. Not a learned baseline — see README.
    start_hour: int | None = Field(default=None, ge=0, le=23)
    end_hour: int | None = Field(default=None, ge=0, le=23)
    # Rule-specific named tunables that don't fit the generic fields above
    # (entropy thresholds, speeds, byte multipliers, ...). Each rule declares
    # the keys it accepts and their defaults in DEFAULT_PARAMS.
    params: dict[str, ParamValue] | None = None
    enabled: bool = True


class RuleMetadata(BaseModel):
    """Machine-readable Detection Engine v2 rule interface description."""

    name: str
    description: str
    severity: str
    config: RuleConfig
    mitre_technique: Optional[str] = None
    entity_type: EntityType = "source_ip"
    # RuleConfig field names this rule actually reads, so a UI only offers
    # settings that do something for it.
    tunables: list[str] = Field(default_factory=list)
