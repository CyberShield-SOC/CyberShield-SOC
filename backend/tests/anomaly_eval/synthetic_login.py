"""Seeded synthetic login history for the login_behavior feature set.

Built from scratch against the real feature extractor
(app/ml/features.py:login_behavior_features) and the real rule's gating
(BehavioralAnomalyLoginRule.analyze: event_type == "login_attempt",
status == "SUCCESS", username set). Line numbers are assigned per-factory,
same convention as synthetic_threat_log.py's RecordFactory.

Overlap is built in from the start (population="v2" is the only population
this module produces -- there is no v1): every attack draws its hour and
country from the same vocabulary normal accounts already use. The two axes
an attacker can vary are the hour of day and whether the country is new for
the account; HOUR_POOL and the per-account home-country set are shared
between normal and attack generators so neither axis is a free separator.
"""

from __future__ import annotations

import random
from datetime import datetime, timezone

from app.detection.models import LogRecord

BASE = datetime(2026, 1, 5, tzinfo=timezone.utc)  # a Monday

# Countries normal accounts are based in. Attacks draw new-geo countries from
# OTHER_COUNTRIES -- some of which (the first few) are deliberately common
# across many accounts' histories, to support the new_geo_common_country
# guard case below.
HOME_COUNTRIES = ("US", "CA", "GB", "DE")
OTHER_COUNTRIES = ("FR", "NL", "JP", "BR", "IN", "AU", "SG", "ZA")

# Pooled hour-of-day weights normal logins are drawn from, covering all 24
# hours so no attack hour is literally impossible for a normal account --
# business-core (weight 8), extended business (4), and overnight/weekend
# (1) bands. TAIL_HOURS (weight 1) and MODERATE_HOURS (weight 4) are real,
# populated bands a normal account occasionally lands in (support, on-call,
# different timezones); COMMON_HOURS (weight 8) is the bulk of normal mass.
HOUR_WEIGHTS = {h: (8 if 9 <= h <= 16 else 4 if 7 <= h <= 19 else 1) for h in range(24)}
COMMON_HOURS = tuple(h for h, w in HOUR_WEIGHTS.items() if w == 8)
MODERATE_HOURS = tuple(h for h, w in HOUR_WEIGHTS.items() if w == 4)
TAIL_HOURS = tuple(h for h, w in HOUR_WEIGHTS.items() if w == 1)

DOW_WEIGHTS = {0: 10, 1: 10, 2: 10, 3: 10, 4: 10, 5: 2, 6: 2}  # weekday-heavy, not weekday-only

NEW_GEO_BASELINE_RATE = 0.04  # normal accounts occasionally travel
NEW_GEO_ELEVATED_RATE = 0.15  # subtle attacks: mildly elevated, still mostly not new-geo


def _weighted_choice(rng: random.Random, weights: dict[int, int]) -> int:
    keys = list(weights)
    return rng.choices(keys, weights=[weights[k] for k in keys], k=1)[0]


def weighted_day_offset(rng: random.Random, num_days: int) -> int:
    """Pick a day offset from BASE within [0, num_days), weighted by DOW_WEIGHTS
    so history is weekday-heavy but genuinely includes weekends -- a flat
    per-day weight would make 'weekday vs weekend' a free, too-clean signal."""

    offsets = list(range(num_days))
    weights = [DOW_WEIGHTS[(BASE.weekday() + o) % 7] for o in offsets]
    return rng.choices(offsets, weights=weights, k=1)[0]


def _ts(day_offset: int, hour: int, minute: int) -> str:
    base_day = BASE.replace(hour=0, minute=0, second=0)
    from datetime import timedelta

    ts = base_day + timedelta(days=day_offset, hours=hour, minutes=minute)
    return ts.strftime("%Y-%m-%dT%H:%M:%SZ")


class RecordFactory:
    """Builds LogRecords with a per-scenario line counter."""

    def __init__(self) -> None:
        self._line = 0

    def mk(self, ts_str: str, username: str, country: str, *, ip: str = "10.50.0.9") -> LogRecord:
        self._line += 1
        return LogRecord(
            line_number=self._line, timestamp=ts_str, ip_address=ip, username=username,
            event_type="login_attempt", status="SUCCESS", country=country,
        )


def make_profile(rng: random.Random) -> dict:
    """One account's routine: a home country (occasionally two) and nothing else --
    the hour/day distributions are pooled (HOUR_WEIGHTS/DOW_WEIGHTS), not per-account,
    so a per-account 'usual time' is not an extra hidden signal this model doesn't have."""

    home = [rng.choice(HOME_COUNTRIES)]
    if rng.random() < 0.15:
        other = rng.choice([c for c in HOME_COUNTRIES if c != home[0]])
        home.append(other)
    return {"home": home, "seen": set(home)}


def normal_login_records(
    factory: RecordFactory, rng: random.Random, profile: dict, username: str, day_offset: int,
) -> tuple[list[LogRecord], dict]:
    """One normal login for one account on one day. Returns (records, meta) where
    meta records whether this login was a (rare) new-geo event, for diagnostics."""

    hour = _weighted_choice(rng, HOUR_WEIGHTS)
    minute = rng.randint(0, 59)
    is_travel = rng.random() < NEW_GEO_BASELINE_RATE
    if is_travel:
        candidates = [c for c in HOME_COUNTRIES + OTHER_COUNTRIES if c not in profile["seen"]]
        country = rng.choice(candidates) if candidates else rng.choice(profile["home"])
    else:
        country = rng.choice(profile["home"])
    new_geo = country not in profile["seen"]
    profile["seen"].add(country)
    record = factory.mk(_ts(day_offset, hour, minute), username, country)
    return [record], {"hour": hour, "is_new_geo": new_geo, "country": country}


# ------------------------------------------------------------ overlap attacks
#
# Each attack is one login event for a dedicated attacker account (so its own
# "known countries" baseline starts empty, like any account's would). Named
# departures from the shared normal vocabulary, stated explicitly -- "subtle"
# variants land in a band real normal accounts also occasionally produce
# (MODERATE_HOURS, or the elevated-but-not-certain new-geo rate), not a
# deterministic tell, mirroring threat_log's "subtle scan: inside the normal
# range" design:
#   - odd_hour_loud:    known country, hour from TAIL_HOURS (weight 1 -- rare, not impossible)
#   - odd_hour_subtle:  known country, hour from MODERATE_HOURS (weight 4 -- mildly uncommon)
#   - new_geo_loud:     new country (certain), hour from COMMON_HOURS
#   - new_geo_subtle:   new country at NEW_GEO_ELEVATED_RATE (mostly not), hour from COMMON_HOURS
#   - combined_loud:    new country (certain) AND hour from TAIL_HOURS
#   - combined_subtle:  new country at NEW_GEO_ELEVATED_RATE AND hour from MODERATE_HOURS
#   - new_geo_common_country (guard case): new for this account, but the country
#     is common across the other accounts in the scenario -- this feature set has
#     no org-wide country-rarity signal, so this case is expected to evade.

OVERLAP_ATTACKS = {
    "odd_hour_loud": {"hour_pool": TAIL_HOURS, "new_geo_rate": 0.0},
    "odd_hour_subtle": {"hour_pool": MODERATE_HOURS, "new_geo_rate": 0.0},
    "new_geo_loud": {"hour_pool": COMMON_HOURS, "new_geo_rate": 1.0},
    "new_geo_subtle": {"hour_pool": COMMON_HOURS, "new_geo_rate": NEW_GEO_ELEVATED_RATE},
    "combined_loud": {"hour_pool": TAIL_HOURS, "new_geo_rate": 1.0},
    "combined_subtle": {"hour_pool": MODERATE_HOURS, "new_geo_rate": NEW_GEO_ELEVATED_RATE},
}


def overlap_attack_record(
    factory: RecordFactory, rng: random.Random, name: str, username: str, day_offset: int, *, home_country: str,
) -> tuple[LogRecord, dict]:
    """One named v2 attack login. `home_country` is a country NOT yet seen for this
    attacker account, used as the 'known' country when the new-geo roll misses."""

    params = OVERLAP_ATTACKS[name]
    hour = rng.choice(params["hour_pool"])
    minute = rng.randint(0, 59)
    is_new_geo = rng.random() < params["new_geo_rate"]
    country = rng.choice(OTHER_COUNTRIES) if is_new_geo else home_country
    record = factory.mk(_ts(day_offset, hour, minute), username, country)
    return record, {"hour": hour, "is_new_geo": is_new_geo, "country": country}


def guard_case_record(
    factory: RecordFactory, rng: random.Random, username: str, day_offset: int, *, common_country: str,
) -> tuple[LogRecord, dict]:
    """new_geo_common_country: new for this account, common across the org.
    Hour is drawn from COMMON_HOURS so only the (missing) org-wide country-rarity
    signal is being tested, not the hour axis."""

    hour = rng.choice(COMMON_HOURS)
    minute = rng.randint(0, 59)
    record = factory.mk(_ts(day_offset, hour, minute), username, common_country)
    return record, {"hour": hour, "is_new_geo": True, "country": common_country}


def account_login_features(hour: int, is_new_geo: bool) -> dict[str, float]:
    """Diagnostic summary of one login: raw hour (not cyclic) and the raw
    is_new_geo flag -- what an analyst reads off a log line. Not the model's
    actual (cyclic-encoded) inputs; used only for the single-feature-AUC proof."""

    return {"hour": float(hour), "is_new_geo": 1.0 if is_new_geo else 0.0}
