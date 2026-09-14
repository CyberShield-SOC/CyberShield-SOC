"""
Feature extraction for the login-behavior IsolationForest pilot.

Pilot #1 from the feasibility doc: a learned per-account "is this login's
timing/geo combination normal" score, extending off_hours_login (a fixed
06:00-20:00 window) and first_seen_geo_asn (a single new-country/new-ASN
flag) into a joint, learned judgment across both at once — the thing a
single threshold rule can't express. Every feature here is derivable from
any auth log; no CSV/JSON-only columns required.
"""

from __future__ import annotations

import math
from datetime import datetime, timezone

FEATURE_SET = "login_behavior"
ENTITY_TYPE = "account"

# Order matters: this is the exact column order every vector uses, at both
# training and scoring time. A model's `feature_names` pins the order it was
# trained with; scoring refuses to run if the two ever disagree (see
# app/detection/rules/behavioral_anomaly_login.py).
FEATURE_NAMES: tuple[str, ...] = ("hour_sin", "hour_cos", "dow_sin", "dow_cos", "is_new_geo")


def login_behavior_features(ts: datetime, *, is_new_geo: bool) -> dict[str, float]:
    """
    One feature vector for one successful login event.

    hour/day-of-week are cyclically encoded (sin/cos pairs) so 23:59 and
    00:01 land next to each other instead of at opposite ends of a raw 0-23
    scale. `is_new_geo` reuses first_seen_geo_asn's own "have we seen this
    country for this account before" judgment (see
    app/detection/rules/first_seen_geo_asn.py) rather than recomputing it,
    so an account with no geo data at all just always gets 0.0 here — never
    a crash, never a guess.
    """

    utc = ts.astimezone(timezone.utc)
    hour = utc.hour + utc.minute / 60
    dow = utc.weekday()
    return {
        "hour_sin": math.sin(2 * math.pi * hour / 24),
        "hour_cos": math.cos(2 * math.pi * hour / 24),
        "dow_sin": math.sin(2 * math.pi * dow / 7),
        "dow_cos": math.cos(2 * math.pi * dow / 7),
        "is_new_geo": 1.0 if is_new_geo else 0.0,
    }


def vector(features: dict[str, float], feature_names: list[str] | tuple[str, ...] = FEATURE_NAMES) -> list[float]:
    """Features dict -> ordered list, in the schema a model expects."""

    return [float(features[name]) for name in feature_names]
