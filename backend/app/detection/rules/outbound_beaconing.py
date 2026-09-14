from __future__ import annotations

import statistics
from collections import defaultdict
from ipaddress import ip_address, ip_network

from app.detection._ts import parse_ts, ts_to_str
from app.detection.geoip import is_public_ip
from app.detection.models import Alert, LogRecord
from app.detection.rules._host_alerts import endpoint_id
from app.detection.rules.base import BaseRule


def _is_internal(value: str | None) -> bool:
    if not value:
        return False
    try:
        address = ip_address(value)
    except ValueError:
        return False
    return address.is_private and not address.is_loopback


class OutboundBeaconingRule(BaseRule):
    """Fires when an internal host connects to the same external destination
    and port at suspiciously regular intervals — command-and-control
    check-ins rather than human browsing.

    Needs connection events with source IP, destination IP, and timestamps
    (firewall logs or CSV/JSON flow exports). Connections closer together
    than params.dedupe_seconds collapse into one (a single session often
    logs several lines). A pair fires when it has >= threshold connections,
    a median interval between params.min_interval_seconds and
    params.max_interval_seconds, and jitter (stdev/mean of the middle 80% of
    intervals) <= params.max_jitter_percent. Update servers, NTP, and
    monitoring endpoints that poll on a timer belong in `allowlist`
    (IPs or CIDRs). Evaluated within one upload.
    """

    name = "outbound_beaconing"
    description = "An internal host made regular, low-jitter connections to one external destination."
    severity = "HIGH"
    mitre_technique = "T1071"
    entity_type = "host"
    confidence = 60
    DEFAULT_PARAMS = {
        "max_jitter_percent": 15.0,
        "min_interval_seconds": 10,
        "max_interval_seconds": 7200,
        "dedupe_seconds": 2,
    }

    def __init__(
        self,
        threshold: int = 10,
        cooldown_seconds: int = 21600,
        allowlist: list[str] | None = None,
        params: dict | None = None,
    ):
        self.threshold = threshold
        self.cooldown_seconds = cooldown_seconds
        self.allowlist = allowlist
        self.params = self.merge_params(params)
        self._allowed_networks = []
        for item in allowlist or ():
            try:
                self._allowed_networks.append(ip_network(item.strip(), strict=False))
            except ValueError:
                continue

    def _allowed(self, value: str) -> bool:
        address = ip_address(value)
        return any(address.version == net.version and address in net for net in self._allowed_networks)

    def analyze(self, records: list[LogRecord], db=None) -> list[Alert]:
        pairs: dict[tuple[str, str, int | None], list] = defaultdict(list)
        for record in records:
            if not (_is_internal(record.ip_address) and is_public_ip(record.dest_ip)):
                continue
            if self._allowed(record.dest_ip):
                continue
            ts = parse_ts(record.timestamp)
            if ts is not None:
                pairs[(record.ip_address, record.dest_ip, record.port)].append((ts, record))

        dedupe = float(self.params["dedupe_seconds"])
        alerts: list[Alert] = []
        for (source, destination, port), events in pairs.items():
            events.sort(key=lambda item: item[0])
            connections = [events[0]]
            for ts, record in events[1:]:
                if (ts - connections[-1][0]).total_seconds() > dedupe:
                    connections.append((ts, record))
            if len(connections) < self.threshold:
                continue

            intervals = sorted(
                (later[0] - earlier[0]).total_seconds()
                for earlier, later in zip(connections, connections[1:])
            )
            trim = len(intervals) // 10
            core = intervals[trim:len(intervals) - trim] if trim else intervals
            median = statistics.median(core)
            mean = statistics.fmean(core)
            if not (float(self.params["min_interval_seconds"]) <= median <= float(self.params["max_interval_seconds"])):
                continue
            jitter = (statistics.pstdev(core) / mean * 100) if mean else 100.0
            if jitter > float(self.params["max_jitter_percent"]):
                continue

            sample = connections[0][1]
            port_label = f":{port}" if port else ""
            alerts.append(Alert(
                rule=self.name,
                severity=self.severity,
                source_ip=source,
                hostname=sample.hostname,
                count=len(connections),
                time_window_seconds=int((connections[-1][0] - connections[0][0]).total_seconds()),
                first_seen=ts_to_str(connections[0][0]),
                last_seen=ts_to_str(connections[-1][0]),
                description=(
                    f"Possible beaconing: {source} connected to {destination}{port_label} "
                    f"{len(connections)} times every ~{median:.0f}s (jitter {jitter:.1f}%)."
                ),
                matched_line_numbers=[r.line_number for _, r in connections],
                mitre_technique=self.mitre_technique,
                confidence=self.confidence,
                entity_type=self.entity_type,
                entity_id=endpoint_id(sample, source),
                evidence={
                    "destination_ip": destination,
                    "destination_port": port,
                    "connections": len(connections),
                    "median_interval_seconds": round(median, 1),
                    "jitter_percent": round(jitter, 1),
                    "bytes_out_total": sum(r.bytes_out or 0 for _, r in connections) or None,
                },
            ))
        return alerts
