from __future__ import annotations

from app.detection._ts import parse_ts, ts_to_str
from app.detection.geoip import is_public_ip
from app.detection.models import Alert, LogRecord
from app.detection.rules.base import BaseRule
from app.repositories.baseline_repository import get_baseline, set_baseline

BASELINE_KEY = "known_geo"
_MAX_REMEMBERED = 100


class FirstSeenGeoAsnRule(BaseRule):
    """Fires when an account logs in successfully from a country or ASN it
    has never used before.

    Each account's known countries/ASNs are learned from its own successful
    logins and kept in entity_baselines across uploads. Nothing fires until
    the account has params.min_history prior geolocated logins, so a brand
    new account (or a fresh deployment) doesn't alert on every first
    sighting. Geo data comes from the log or a configured GeoIP database.
    `allowlist` holds usernames (travelling staff) to skip.
    """

    name = "first_seen_geo_asn"
    description = "An account logged in from a country or network (ASN) it has never used."
    severity = "MEDIUM"
    mitre_technique = "T1078"
    entity_type = "account"
    confidence = 50
    DEFAULT_PARAMS = {"min_history": 5}

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
                and (record.country or record.asn)
                and is_public_ip(record.ip_address)
                and record.username.lower() not in self._allowed
                for ts in [parse_ts(record.timestamp)]
                if ts is not None
            ),
            key=lambda item: item[0],
        )

        min_history = int(self.params["min_history"])
        state: dict[str, dict] = {}
        alerts: list[Alert] = []

        for ts, record in logins:
            user = record.username
            if user not in state:
                stored = (
                    get_baseline(db, entity_type="account", entity_id=user, baseline_key=BASELINE_KEY)
                    if db is not None else None
                ) or {}
                state[user] = {
                    "countries": list(stored.get("countries") or []),
                    "asns": list(stored.get("asns") or []),
                    "logins": int(stored.get("logins") or 0),
                }
            known = state[user]

            reasons = []
            if record.country and record.country not in known["countries"]:
                reasons.append(f"country {record.country}")
            if record.asn and record.asn not in known["asns"]:
                reasons.append(f"ASN {record.asn}")

            if reasons and known["logins"] >= min_history:
                seen = ts_to_str(ts)
                alerts.append(Alert(
                    rule=self.name,
                    severity=self.severity,
                    source_ip=record.ip_address,
                    username=user,
                    hostname=record.hostname,
                    count=1,
                    time_window_seconds=0,
                    first_seen=seen,
                    last_seen=seen,
                    description=(
                        f"'{user}' logged in from a never-before-seen {' and '.join(reasons)} "
                        f"({record.ip_address}) after {known['logins']} prior logins."
                    ),
                    matched_line_numbers=[record.line_number],
                    mitre_technique=self.mitre_technique,
                    confidence=self.confidence,
                    entity_type=self.entity_type,
                    entity_id=user,
                    evidence={
                        "new_country": record.country if record.country not in known["countries"] else None,
                        "new_asn": record.asn if record.asn and record.asn not in known["asns"] else None,
                        "known_countries": known["countries"][:20],
                        "known_asns": known["asns"][:20],
                        "prior_logins": known["logins"],
                    },
                ))

            if record.country and record.country not in known["countries"]:
                known["countries"] = (known["countries"] + [record.country])[-_MAX_REMEMBERED:]
            if record.asn and record.asn not in known["asns"]:
                known["asns"] = (known["asns"] + [record.asn])[-_MAX_REMEMBERED:]
            known["logins"] += 1

        if db is not None:
            for user, known in state.items():
                set_baseline(db, entity_type="account", entity_id=user, baseline_key=BASELINE_KEY, value=known)
        return alerts
