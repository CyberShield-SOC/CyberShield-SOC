from __future__ import annotations

import math

from app.detection._ts import parse_ts, ts_to_str
from app.detection.geoip import is_public_ip
from app.detection.models import Alert, LogRecord
from app.detection.rules.base import BaseRule
from app.repositories.baseline_repository import get_baseline, set_baseline

BASELINE_KEY = "last_geo_login"
_EARTH_RADIUS_KM = 6371.0


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlmb = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlmb / 2) ** 2
    return 2 * _EARTH_RADIUS_KM * math.asin(math.sqrt(a))


class ImpossibleTravelRule(BaseRule):
    """Fires when one account logs in successfully from two locations whose
    distance couldn't be covered in the elapsed time.

    Needs latitude/longitude for the login's public source IP — supplied by
    the log (IdP/VPN/SIEM exports with geo columns) or by a configured local
    GeoIP database (see app/detection/geoip.py). Consecutive logins are
    compared, including the account's last geolocated login from an earlier
    upload (entity_baselines). Fires when the implied speed exceeds
    params.max_speed_kmh over at least params.min_distance_km. Known VPN
    egress IPs or accounts that legitimately share credentials belong in
    `allowlist` (IPs or usernames).
    """

    name = "impossible_travel"
    description = "An account logged in from two locations too far apart for the time between them."
    severity = "HIGH"
    mitre_technique = "T1078"
    entity_type = "account"
    confidence = 70
    DEFAULT_PARAMS = {"max_speed_kmh": 1000.0, "min_distance_km": 500.0}

    def __init__(
        self,
        cooldown_seconds: int = 3600,
        allowlist: list[str] | None = None,
        params: dict | None = None,
    ):
        self.cooldown_seconds = cooldown_seconds
        self.allowlist = allowlist
        self.params = self.merge_params(params)
        self._allowed = {item.strip().lower() for item in (allowlist or ())}

    def analyze(self, records: list[LogRecord], db=None) -> list[Alert]:
        logins = sorted(
            (
                (ts, record)
                for record in records
                if record.event_type == "login_attempt"
                and record.status == "SUCCESS"
                and record.username
                and record.latitude is not None
                and record.longitude is not None
                and is_public_ip(record.ip_address)
                and record.username.lower() not in self._allowed
                and record.ip_address not in self._allowed
                for ts in [parse_ts(record.timestamp)]
                if ts is not None
            ),
            key=lambda item: item[0],
        )

        max_speed = float(self.params["max_speed_kmh"])
        min_distance = float(self.params["min_distance_km"])
        previous: dict[str, dict] = {}
        alerts: list[Alert] = []

        for ts, record in logins:
            user = record.username
            prior = previous.get(user)
            if prior is None and db is not None:
                prior = get_baseline(db, entity_type="account", entity_id=user, baseline_key=BASELINE_KEY)
            current = {
                "ts": ts_to_str(ts), "ip": record.ip_address, "country": record.country,
                "lat": record.latitude, "lon": record.longitude, "line": record.line_number,
            }

            prior_ts = parse_ts(prior.get("ts")) if prior else None
            if prior and prior_ts is not None and ts >= prior_ts and prior.get("ip") != record.ip_address:
                distance = haversine_km(prior["lat"], prior["lon"], record.latitude, record.longitude)
                hours = (ts - prior_ts).total_seconds() / 3600
                speed = distance / hours if hours > 0 else math.inf
                if distance >= min_distance and speed > max_speed:
                    lines = [n for n in (prior.get("line") if user in previous else None, record.line_number) if n]
                    speed_text = "instantly" if math.isinf(speed) else f"at {speed:,.0f} km/h"
                    alerts.append(Alert(
                        rule=self.name,
                        severity=self.severity,
                        source_ip=record.ip_address,
                        username=user,
                        hostname=record.hostname,
                        count=2,
                        time_window_seconds=int((ts - prior_ts).total_seconds()),
                        first_seen=prior["ts"],
                        last_seen=ts_to_str(ts),
                        description=(
                            f"Impossible travel for '{user}': {prior.get('ip')} "
                            f"({prior.get('country') or '?'}) then {record.ip_address} "
                            f"({record.country or '?'}), {distance:,.0f} km apart, {speed_text}."
                        ),
                        matched_line_numbers=lines,
                        mitre_technique=self.mitre_technique,
                        confidence=self.confidence,
                        entity_type=self.entity_type,
                        entity_id=user,
                        evidence={
                            "from_ip": prior.get("ip"), "from_country": prior.get("country"),
                            "to_ip": record.ip_address, "to_country": record.country,
                            "distance_km": round(distance),
                            "elapsed_minutes": round((ts - prior_ts).total_seconds() / 60, 1),
                            "speed_kmh": None if math.isinf(speed) else round(speed),
                        },
                    ))
            previous[user] = current

        if db is not None:
            for user, state in previous.items():
                stored = get_baseline(db, entity_type="account", entity_id=user, baseline_key=BASELINE_KEY)
                stored_ts = parse_ts(stored.get("ts")) if stored else None
                if stored_ts is None or parse_ts(state["ts"]) >= stored_ts:
                    set_baseline(db, entity_type="account", entity_id=user, baseline_key=BASELINE_KEY,
                                 value={key: value for key, value in state.items() if key != "line"})
        return alerts
