from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone

from sqlalchemy import select

from app.detection._ts import parse_ts, ts_to_str
from app.detection.models import Alert, LogRecord
from app.detection.rules.base import BaseRule
from app.models.host_heartbeat import HostHeartbeat

# Weight of the newest batch when smoothing a host's reporting cadence.
_CADENCE_ALPHA = 0.3
_MIN_GAPS_FOR_CADENCE = 5


@dataclass
class HostState:
    hostname: str
    first_seen_at: datetime
    last_seen_at: datetime
    event_count: int = 0
    cadence_seconds: float | None = None
    silence_alerted_for: datetime | None = None
    last_line_number: int | None = None
    row: HostHeartbeat | None = field(default=None, repr=False)


@dataclass
class SilenceFinding:
    hostname: str
    silent_since: datetime
    silent_until: datetime
    cadence_seconds: float | None
    threshold_seconds: float
    ongoing: bool
    line_numbers: list[int]

    @property
    def silence_seconds(self) -> float:
        return (self.silent_until - self.silent_since).total_seconds()


def _utc(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def p90_gap(timestamps: list[datetime]) -> float | None:
    gaps = sorted(
        (later - earlier).total_seconds()
        for earlier, later in zip(timestamps, timestamps[1:])
    )
    if len(gaps) < _MIN_GAPS_FOR_CADENCE:
        return None
    return gaps[int(0.9 * (len(gaps) - 1))]


class HostLogSilenceRule(BaseRule):
    """Fires when a host with an established reporting cadence stops sending
    events for more than `threshold` × its usual gap (never less than
    `window_seconds`, never more than params.max_silence_seconds).

    Two cases:
    - a gap inside the data: the host went quiet, then resumed;
    - an ongoing silence: the host's last event is older than a reference
      time — the newest event in the upload, or the current time when
      triggered via POST /detection/host-silence/check. Raised once per
      silence episode.

    Cadence and last-seen state live in `host_heartbeats`, so silence is
    tracked across uploads. There is no background scheduler: an ongoing
    silence is only noticed when something uploads or calls the check
    endpoint (an external cron can call it). Without a database session
    only gaps within the one upload are evaluated.
    """

    name = "host_log_silence"
    description = "A host with an established reporting cadence stopped sending logs."
    severity = "HIGH"
    mitre_technique = "T1562.006"
    entity_type = "host"
    confidence = 55
    DEFAULT_PARAMS = {"min_events": 20, "max_silence_seconds": 86400}

    def __init__(
        self,
        threshold: int = 5,
        window_seconds: int = 1800,
        cooldown_seconds: int = 0,
        params: dict | None = None,
    ):
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.cooldown_seconds = cooldown_seconds
        self.params = self.merge_params(params)

    def silence_threshold(self, cadence: float | None) -> float:
        floor = float(self.window_seconds)
        scaled = self.threshold * cadence if cadence else floor
        return min(float(self.params["max_silence_seconds"]), max(floor, scaled))

    def is_established(self, state: HostState) -> bool:
        return state.event_count >= int(self.params["min_events"])

    # ── state ────────────────────────────────────────────────────────────────

    def load_states(self, db) -> dict[str, HostState]:
        if db is None:
            return {}
        rows = db.scalars(select(HostHeartbeat)).all()
        return {
            row.hostname: HostState(
                hostname=row.hostname,
                first_seen_at=_utc(row.first_seen_at),
                last_seen_at=_utc(row.last_seen_at),
                event_count=row.event_count,
                cadence_seconds=row.cadence_seconds,
                silence_alerted_for=_utc(row.silence_alerted_for) if row.silence_alerted_for else None,
                row=row,
            )
            for row in rows
        }

    def save_states(self, db, states: dict[str, HostState]) -> None:
        if db is None:
            return
        for state in states.values():
            row = state.row
            if row is None:
                row = HostHeartbeat(hostname=state.hostname, first_seen_at=state.first_seen_at, last_seen_at=state.last_seen_at)
                db.add(row)
                state.row = row
            row.first_seen_at = state.first_seen_at
            row.last_seen_at = state.last_seen_at
            row.event_count = state.event_count
            row.cadence_seconds = state.cadence_seconds
            row.silence_alerted_for = state.silence_alerted_for
        db.flush()

    # ── evaluation ───────────────────────────────────────────────────────────

    def ongoing_silences(self, states: dict[str, HostState], reference: datetime) -> list[SilenceFinding]:
        findings = []
        for state in states.values():
            if not self.is_established(state) or state.last_seen_at >= reference:
                continue
            if state.silence_alerted_for == state.last_seen_at:
                continue
            threshold = self.silence_threshold(state.cadence_seconds)
            if (reference - state.last_seen_at).total_seconds() <= threshold:
                continue
            state.silence_alerted_for = state.last_seen_at
            findings.append(SilenceFinding(
                hostname=state.hostname,
                silent_since=state.last_seen_at,
                silent_until=reference,
                cadence_seconds=state.cadence_seconds,
                threshold_seconds=threshold,
                ongoing=True,
                line_numbers=[state.last_line_number] if state.last_line_number else [],
            ))
        return findings

    def to_alert(self, finding: SilenceFinding) -> Alert:
        minutes = finding.silence_seconds / 60
        state = "has not reported" if finding.ongoing else "stopped reporting"
        description = (
            f"Host {finding.hostname} {state} for {minutes:.0f} min "
            f"(since {ts_to_str(finding.silent_since)}; expected gap ≤ {finding.threshold_seconds / 60:.0f} min)."
        )
        return Alert(
            rule=self.name,
            severity=self.severity,
            hostname=finding.hostname,
            count=1,
            time_window_seconds=int(finding.silence_seconds),
            first_seen=ts_to_str(finding.silent_since),
            last_seen=ts_to_str(finding.silent_until),
            description=description,
            matched_line_numbers=finding.line_numbers,
            mitre_technique=self.mitre_technique,
            confidence=self.confidence,
            entity_type="host",
            entity_id=finding.hostname,
            evidence={
                "silent_since": ts_to_str(finding.silent_since),
                "silent_until": ts_to_str(finding.silent_until),
                "silence_seconds": int(finding.silence_seconds),
                "expected_cadence_seconds": round(finding.cadence_seconds, 1) if finding.cadence_seconds else None,
                "threshold_seconds": int(finding.threshold_seconds),
                "ongoing": finding.ongoing,
            },
        )

    def analyze(self, records: list[LogRecord], db=None) -> list[Alert]:
        by_host: dict[str, list[tuple[datetime, int]]] = defaultdict(list)
        for record in records:
            ts = parse_ts(record.timestamp)
            if record.hostname and ts is not None:
                by_host[record.hostname].append((ts, record.line_number))
        if not by_host:
            return []

        states = self.load_states(db)
        findings: list[SilenceFinding] = []
        reference = max(ts for events in by_host.values() for ts, _ in events)

        for hostname, events in by_host.items():
            events.sort()
            state = states.get(hostname)
            if state is None:
                state = HostState(hostname=hostname, first_seen_at=events[0][0], last_seen_at=events[0][0])
                states[hostname] = state
                previous: tuple[datetime, int | None] | None = None
            else:
                previous = (state.last_seen_at, None)

            batch_cadence = p90_gap([ts for ts, _ in events])
            if batch_cadence is not None:
                state.cadence_seconds = (
                    batch_cadence if state.cadence_seconds is None
                    else (1 - _CADENCE_ALPHA) * state.cadence_seconds + _CADENCE_ALPHA * batch_cadence
                )

            for ts, line_number in events:
                if previous is not None and ts > previous[0] and self.is_established(state):
                    threshold = self.silence_threshold(state.cadence_seconds)
                    gap = (ts - previous[0]).total_seconds()
                    if gap > threshold and state.silence_alerted_for != previous[0]:
                        findings.append(SilenceFinding(
                            hostname=hostname,
                            silent_since=previous[0],
                            silent_until=ts,
                            cadence_seconds=state.cadence_seconds,
                            threshold_seconds=threshold,
                            ongoing=False,
                            line_numbers=[n for n in (previous[1], line_number) if n],
                        ))
                if previous is None or ts >= previous[0]:
                    previous = (ts, line_number)
                state.event_count += 1

            state.first_seen_at = min(state.first_seen_at, events[0][0])
            if events[-1][0] >= state.last_seen_at:
                state.last_seen_at = events[-1][0]
                state.last_line_number = events[-1][1]

        findings.extend(self.ongoing_silences(states, reference))
        self.save_states(db, states)
        return [self.to_alert(finding) for finding in findings]
