from __future__ import annotations

from collections import defaultdict, deque

from app.detection._ts import parse_ts, ts_to_str
from app.detection.models import Alert, LogRecord
from app.detection.rules.base import BaseRule


class PortScanRule(BaseRule):
    """Fires when one source IP generates >= threshold port-scan events within
    window_seconds, or — for connection logs — probes >= threshold distinct
    ports on one destination host within window_seconds."""

    name = "port_scan"
    description = "One source IP generates repeated port-scan events in a short window."
    severity = "MEDIUM"
    mitre_technique = "T1046"
    entity_type = "source_ip"
    confidence = 60

    def __init__(self, threshold: int = 10, window_seconds: int = 60):
        self.threshold = threshold
        self.window_seconds = window_seconds

    def analyze(self, records: list[LogRecord], db=None) -> list[Alert]:
        candidates = [
            r for r in records
            if r.event_type == "port_scan"
            and r.ip_address
        ]

        by_ip: dict[str, list[LogRecord]] = defaultdict(list)
        for r in candidates:
            by_ip[r.ip_address].append(r)

        alerts: list[Alert] = []
        for ip, recs in by_ip.items():
            timed = sorted(
                [(r, parse_ts(r.timestamp)) for r in recs],
                key=lambda x: (x[1] is None, x[1]),
            )
            window: deque = deque()

            for rec, ts in timed:
                if ts is None:
                    continue
                window.append((rec, ts))
                while window and (ts - window[0][1]).total_seconds() > self.window_seconds:
                    window.popleft()

                if len(window) >= self.threshold:
                    matched = list(window)
                    alerts.append(Alert(
                        rule=self.name,
                        severity=self.severity,
                        source_ip=ip,
                        username=matched[0][0].username,
                        count=len(matched),
                        time_window_seconds=self.window_seconds,
                        first_seen=ts_to_str(matched[0][1]),
                        last_seen=ts_to_str(matched[-1][1]),
                        description=(
                            f"Port scan detected from {ip}: "
                            f"{len(matched)} scan events within {self.window_seconds}s."
                        ),
                        matched_line_numbers=[r.line_number for r, _ in matched],
                        mitre_technique=self.mitre_technique,
                        confidence=self.confidence,
                        entity_type=self.entity_type,
                        entity_id=ip,
                    ))
                    window.clear()

        alerts.extend(self._vertical_scans(records))
        return alerts

    def _vertical_scans(self, records: list[LogRecord]) -> list[Alert]:
        """Connection data (source, destination, port) — e.g. firewall logs —
        rarely labels events "port_scan". Detect the behaviour directly:
        >= threshold distinct destination ports on one host from one source."""

        by_pair: dict[tuple[str, str], list] = defaultdict(list)
        for record in records:
            if record.event_type == "port_scan" or not (record.ip_address and record.dest_ip and record.port):
                continue
            ts = parse_ts(record.timestamp)
            if ts is not None:
                by_pair[(record.ip_address, record.dest_ip)].append((ts, record))

        alerts: list[Alert] = []
        for (source, destination), events in by_pair.items():
            events.sort(key=lambda item: item[0])
            window: deque = deque()
            for ts, record in events:
                window.append((ts, record))
                while (ts - window[0][0]).total_seconds() > self.window_seconds:
                    window.popleft()
                ports = {r.port for _, r in window}
                if len(ports) < self.threshold:
                    continue
                matched = list(window)
                alerts.append(Alert(
                    rule=self.name,
                    severity=self.severity,
                    source_ip=source,
                    hostname=record.hostname,
                    count=len(ports),
                    time_window_seconds=self.window_seconds,
                    first_seen=ts_to_str(matched[0][0]),
                    last_seen=ts_to_str(ts),
                    description=(
                        f"Port scan detected from {source}: {len(ports)} distinct ports on "
                        f"{destination} within {self.window_seconds}s."
                    ),
                    matched_line_numbers=[r.line_number for _, r in matched],
                    mitre_technique=self.mitre_technique,
                    confidence=self.confidence,
                    entity_type=self.entity_type,
                    entity_id=source,
                    evidence={"destination_ip": destination, "ports_sample": sorted(ports)[:25]},
                ))
                window.clear()
        return alerts
