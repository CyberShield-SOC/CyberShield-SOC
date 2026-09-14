from __future__ import annotations

from collections import defaultdict, deque

from app.detection._ts import parse_ts, ts_to_str
from app.detection.models import Alert, LogRecord
from app.detection.rules.base import BaseRule


class HostSweepRule(BaseRule):
    """Fires when one source IP contacts the same destination port on
    >= threshold distinct hosts within window_seconds — the horizontal
    counterpart of port_scan (one port, many hosts).

    Needs connection events carrying source IP, destination IP, and
    destination port: firewall kernel logs (UFW/iptables SRC=/DST=/DPT=) or
    CSV/JSON flow exports. Both allowed and blocked attempts count.
    Authorised scanners (vulnerability scanners, monitoring) belong in
    `allowlist`.
    """

    name = "host_sweep"
    description = "One source IP probed the same port across many hosts."
    severity = "MEDIUM"
    mitre_technique = "T1046"
    entity_type = "source_ip"
    confidence = 70

    def __init__(
        self,
        threshold: int = 10,
        window_seconds: int = 300,
        cooldown_seconds: int = 1800,
        allowlist: list[str] | None = None,
    ):
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.cooldown_seconds = cooldown_seconds
        self.allowlist = allowlist
        self._allowed = {item.strip() for item in (allowlist or ())}

    def analyze(self, records: list[LogRecord], db=None) -> list[Alert]:
        groups: dict[tuple[str, int], list] = defaultdict(list)
        for record in records:
            if not (record.ip_address and record.dest_ip and record.port):
                continue
            if record.ip_address in self._allowed or record.ip_address == record.dest_ip:
                continue
            ts = parse_ts(record.timestamp)
            if ts is not None:
                groups[(record.ip_address, record.port)].append((ts, record))

        alerts: list[Alert] = []
        for (source, port), events in groups.items():
            events.sort(key=lambda item: item[0])
            window: deque = deque()
            for ts, record in events:
                window.append((ts, record))
                while (ts - window[0][0]).total_seconds() > self.window_seconds:
                    window.popleft()
                hosts = {r.dest_ip for _, r in window}
                if len(hosts) < self.threshold:
                    continue
                matched = list(window)
                alerts.append(Alert(
                    rule=self.name,
                    severity=self.severity,
                    source_ip=source,
                    hostname=record.hostname,
                    count=len(hosts),
                    time_window_seconds=self.window_seconds,
                    first_seen=ts_to_str(matched[0][0]),
                    last_seen=ts_to_str(ts),
                    description=(
                        f"Host sweep from {source}: port {port} contacted on {len(hosts)} "
                        f"distinct hosts within {self.window_seconds}s."
                    ),
                    matched_line_numbers=[r.line_number for _, r in matched],
                    mitre_technique=self.mitre_technique,
                    confidence=self.confidence,
                    entity_type=self.entity_type,
                    entity_id=source,
                    evidence={
                        "destination_port": port,
                        "distinct_hosts": len(hosts),
                        "hosts_sample": sorted(hosts)[:20],
                        "blocked": sum(1 for _, r in matched if r.status == "FAILED"),
                    },
                ))
                window.clear()
        return alerts
