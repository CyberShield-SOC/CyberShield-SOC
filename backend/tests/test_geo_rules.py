"""Group B geo identity rules and GeoIP enrichment."""

from __future__ import annotations

import sys
from pathlib import Path
from uuid import uuid4

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.detection.geoip import enrich_records
from app.detection.models import LogRecord
from app.detection.rules.first_seen_geo_asn import FirstSeenGeoAsnRule
from app.detection.rules.impossible_travel import ImpossibleTravelRule, haversine_km

NYC = ("US", "7922", 40.7128, -74.0060)
AMS = ("NL", "9009", 52.3676, 4.9041)
BOS = ("US", "7922", 42.3601, -71.0589)


def login(n, user, ip, when, geo, status="SUCCESS"):
    country, asn, lat, lon = geo
    return LogRecord(
        line_number=n, timestamp=when, username=user, ip_address=ip, event_type="login_attempt",
        status=status, country=country, asn=asn, latitude=lat, longitude=lon,
    )


@pytest.mark.no_db
class TestImpossibleTravel:
    def test_fires_on_transatlantic_hop_in_40_minutes(self):
        records = [
            login(1, "carol", "73.12.44.9", "2026-09-10T14:00:00Z", NYC),
            login(2, "carol", "185.107.56.10", "2026-09-10T14:40:00Z", AMS),
        ]
        alerts = ImpossibleTravelRule().analyze(records)
        assert len(alerts) == 1
        assert alerts[0].evidence["distance_km"] > 5000
        assert alerts[0].matched_line_numbers == [1, 2]

    def test_near_miss_plausible_travel(self):
        records = [
            login(1, "carol", "73.12.44.9", "2026-09-10T02:00:00Z", NYC),
            login(2, "carol", "185.107.56.10", "2026-09-10T14:00:00Z", AMS),
        ]
        assert ImpossibleTravelRule().analyze(records) == []

    def test_near_miss_short_distance(self):
        records = [
            login(1, "bob", "73.12.45.9", "2026-09-10T14:00:00Z", NYC),
            login(2, "bob", "73.61.2.14", "2026-09-10T14:20:00Z", BOS),
        ]
        assert ImpossibleTravelRule().analyze(records) == []

    def test_failed_logins_and_private_ips_are_ignored(self):
        records = [
            login(1, "carol", "73.12.44.9", "2026-09-10T14:00:00Z", NYC),
            login(2, "carol", "185.107.56.10", "2026-09-10T14:10:00Z", AMS, status="FAILED"),
            login(3, "carol", "10.0.0.5", "2026-09-10T14:20:00Z", AMS),
        ]
        assert ImpossibleTravelRule().analyze(records) == []

    def test_allowlisted_vpn_egress_ip(self):
        records = [
            login(1, "carol", "73.12.44.9", "2026-09-10T14:00:00Z", NYC),
            login(2, "carol", "185.107.56.10", "2026-09-10T14:40:00Z", AMS),
        ]
        assert ImpossibleTravelRule(allowlist=["185.107.56.10"]).analyze(records) == []

    def test_haversine(self):
        assert 5800 < haversine_km(*NYC[2:], *AMS[2:]) < 5900


class TestImpossibleTravelAcrossUploads:
    def test_previous_upload_location_is_remembered(self, db_session):
        user = f"traveller-{uuid4().hex[:6]}"
        rule = ImpossibleTravelRule()
        assert rule.analyze([login(1, user, "73.12.44.9", "2026-09-10T14:00:00Z", NYC)], db_session) == []
        alerts = rule.analyze([login(1, user, "185.107.56.10", "2026-09-10T14:30:00Z", AMS)], db_session)
        assert len(alerts) == 1
        assert alerts[0].matched_line_numbers == [1]


class TestFirstSeenGeoAsn:
    def history(self, user, count, geo=NYC):
        return [login(i, user, f"73.12.44.{i}", f"2026-09-0{1 + i % 8}T14:00:00Z", geo) for i in range(count)]

    @pytest.mark.no_db
    def test_new_country_after_learning_period_fires(self):
        records = self.history("carol", 5) + [login(99, "carol", "185.107.56.10", "2026-09-10T14:00:00Z", AMS)]
        alerts = FirstSeenGeoAsnRule().analyze(records)
        assert len(alerts) == 1
        assert alerts[0].evidence["new_country"] == "NL"
        assert alerts[0].evidence["new_asn"] == "9009"

    @pytest.mark.no_db
    def test_near_miss_inside_learning_period(self):
        records = self.history("dan", 2) + [login(99, "dan", "185.107.56.10", "2026-09-10T14:00:00Z", AMS)]
        assert FirstSeenGeoAsnRule().analyze(records) == []

    @pytest.mark.no_db
    def test_near_miss_known_location(self):
        records = self.history("bob", 6) + [login(99, "bob", "73.61.2.14", "2026-09-10T14:00:00Z", BOS)]
        assert FirstSeenGeoAsnRule().analyze(records) == []

    @pytest.mark.no_db
    def test_allowlisted_user(self):
        records = self.history("carol", 5) + [login(99, "carol", "185.107.56.10", "2026-09-10T14:00:00Z", AMS)]
        assert FirstSeenGeoAsnRule(allowlist=["carol"]).analyze(records) == []

    def test_history_is_learned_across_uploads(self, db_session):
        user = f"geo-{uuid4().hex[:6]}"
        rule = FirstSeenGeoAsnRule()
        assert rule.analyze(self.history(user, 5), db_session) == []
        assert len(rule.analyze([login(1, user, "185.107.56.10", "2026-09-10T14:00:00Z", AMS)], db_session)) == 1


@pytest.mark.no_db
class TestGeoEnrichment:
    class FakeResolver:
        def __init__(self):
            self.calls = []

        def lookup(self, ip):
            self.calls.append(ip)
            return {"country": "NL", "asn": "9009", "latitude": 52.37, "longitude": 4.9}

    def test_fills_missing_fields_for_public_ips_once_per_ip(self):
        resolver = self.FakeResolver()
        records = [
            LogRecord(line_number=1, ip_address="185.107.56.10"),
            LogRecord(line_number=2, ip_address="185.107.56.10"),
            LogRecord(line_number=3, ip_address="10.0.0.1"),
        ]
        enriched = enrich_records(records, resolver)
        assert enriched[0].country == "NL" and enriched[1].latitude == 52.37
        assert enriched[2].country is None
        assert resolver.calls == ["185.107.56.10"]

    def test_log_supplied_values_win(self):
        record = LogRecord(line_number=1, ip_address="185.107.56.10", country="DE", asn="3320", latitude=1.0, longitude=2.0)
        assert enrich_records([record], self.FakeResolver())[0].country == "DE"

    def test_no_resolver_is_a_no_op(self):
        records = [LogRecord(line_number=1, ip_address="185.107.56.10")]
        assert enrich_records(records, None) is records
