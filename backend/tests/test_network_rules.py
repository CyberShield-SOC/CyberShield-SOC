"""Group C network rules: host_sweep, outbound_beaconing, dns_tunneling,
egress_volume_anomaly, threat_intel_match, and port_scan's vertical path."""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.detection.models import LogRecord
from app.detection.rules.dns_tunneling import DnsTunnelingRule, parent_domain, shannon_entropy
from app.detection.rules.egress_volume_anomaly import EgressVolumeAnomalyRule
from app.detection.rules.host_sweep import HostSweepRule
from app.detection.rules.outbound_beaconing import OutboundBeaconingRule
from app.detection.rules.port_scan import PortScanRule
from app.detection.rules.threat_intel_match import ThreatIntelMatchRule
from app.repositories.threat_intel_repository import classify_indicator, import_feed, parse_feed

BASE = datetime(2026, 9, 10, 14, 0, tzinfo=timezone.utc)


def ts(seconds: float) -> str:
    return (BASE + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def flow(n, src, dst, port, seconds, host=None, bytes_out=None, process=None):
    return LogRecord(
        line_number=n, timestamp=ts(seconds), ip_address=src, dest_ip=dst, port=port,
        hostname=host, bytes_out=bytes_out, process=process, event_type="network_connection",
    )


# ── host_sweep ───────────────────────────────────────────────────────────────

@pytest.mark.no_db
class TestHostSweep:
    def test_fires_on_one_port_across_many_hosts(self):
        records = [flow(i, "203.0.113.9", f"10.0.0.{i}", 22, i * 5) for i in range(1, 11)]
        alerts = HostSweepRule().analyze(records)
        assert len(alerts) == 1
        assert alerts[0].evidence["destination_port"] == 22
        assert alerts[0].mitre_technique == "T1046"

    def test_near_miss_many_hosts_but_different_ports(self):
        records = [flow(i, "203.0.113.9", f"10.0.0.{i}", 1000 + i, i * 5) for i in range(1, 11)]
        assert HostSweepRule().analyze(records) == []

    def test_near_miss_spread_beyond_window(self):
        records = [flow(i, "203.0.113.9", f"10.0.0.{i}", 22, i * 60) for i in range(1, 11)]
        assert HostSweepRule(window_seconds=300).analyze(records) == []

    def test_allowlisted_scanner_is_ignored(self):
        records = [flow(i, "10.9.9.9", f"10.0.0.{i}", 22, i) for i in range(1, 11)]
        assert HostSweepRule(allowlist=["10.9.9.9"]).analyze(records) == []


@pytest.mark.no_db
class TestPortScanVerticalPath:
    def test_many_ports_on_one_host_fires_without_port_scan_label(self):
        records = [flow(i, "198.51.100.1", "10.0.0.5", 20 + i, i) for i in range(10)]
        alerts = PortScanRule().analyze(records)
        assert len(alerts) == 1
        assert alerts[0].evidence["destination_ip"] == "10.0.0.5"

    def test_near_miss_repeated_single_port(self):
        records = [flow(i, "198.51.100.1", "10.0.0.5", 443, i) for i in range(20)]
        assert PortScanRule().analyze(records) == []


# ── outbound_beaconing ───────────────────────────────────────────────────────

@pytest.mark.no_db
class TestOutboundBeaconing:
    def test_regular_callbacks_fire(self):
        records = [flow(i, "10.0.3.14", "45.33.32.156", 8443, i * 60 + (1 if i % 2 else -1), host="ws-114") for i in range(15)]
        alerts = OutboundBeaconingRule().analyze(records)
        assert len(alerts) == 1
        assert alerts[0].entity_id == "ws-114"
        assert alerts[0].evidence["jitter_percent"] < 15

    def test_near_miss_irregular_browsing(self):
        gaps = [3, 50, 7, 240, 12, 600, 30, 90, 15, 400, 8, 75, 20, 300]
        seconds, records = 0, []
        for i, gap in enumerate(gaps):
            seconds += gap
            records.append(flow(i, "10.0.3.20", "140.82.112.3", 443, seconds))
        assert OutboundBeaconingRule().analyze(records) == []

    def test_near_miss_internal_destination(self):
        records = [flow(i, "10.0.3.14", "10.0.9.9", 8443, i * 60) for i in range(15)]
        assert OutboundBeaconingRule().analyze(records) == []

    def test_allowlisted_destination_cidr(self):
        records = [flow(i, "10.0.3.14", "45.33.32.156", 123, i * 60) for i in range(15)]
        assert OutboundBeaconingRule(allowlist=["45.33.32.0/24"]).analyze(records) == []

    def test_firewall_relayed_logs_pivot_on_endpoint_ip_not_firewall_name(self):
        records = [flow(i, "10.0.3.14", "45.33.32.156", 8443, i * 60, host="fw01", process="kernel") for i in range(15)]
        assert OutboundBeaconingRule().analyze(records)[0].entity_id == "10.0.3.14"

    def test_jitter_threshold_is_a_param(self):
        records = [flow(i, "10.0.3.14", "45.33.32.156", 8443, i * 60 + (8 if i % 2 else -8)) for i in range(15)]
        assert OutboundBeaconingRule().analyze(records) == []
        assert len(OutboundBeaconingRule(params={"max_jitter_percent": 40}).analyze(records)) == 1


# ── dns_tunneling ────────────────────────────────────────────────────────────

def dns(n, client, name, seconds, qtype="TXT"):
    return LogRecord(line_number=n, timestamp=ts(seconds), ip_address=client, dns_query=name, dns_query_type=qtype)


@pytest.mark.no_db
class TestDnsTunneling:
    LABELS = [
        "mzxw6ytboi4dsnrzgiztinjwg44dsobygi3tkmzr", "nbswy3dpeb3w64tmmqqq2x7k4ptf1ah9ds0qlkz3",
        "k5sxg43fmfzgq2lpnzsgk4rao5ugk4rann3w4ylsm", "orsxg5bamfzwy3ljnztwk5dfmvzgs43uojsw4ztf",
    ]

    def queries(self, count, client="10.0.5.23"):
        return [
            dns(i, client, f"{self.LABELS[i % 4]}{i:04d}.data.exfil-tunnel.net", i * 5)
            for i in range(count)
        ]

    def test_long_high_entropy_queries_fire(self):
        alerts = DnsTunnelingRule().analyze(self.queries(25))
        assert len(alerts) == 1
        assert alerts[0].evidence["parent_domain"] == "exfil-tunnel.net"
        assert alerts[0].entity_id == "10.0.5.23"

    def test_near_miss_below_threshold(self):
        assert DnsTunnelingRule().analyze(self.queries(10)) == []

    def test_near_miss_short_cdn_names(self):
        records = [dns(i, "10.0.5.23", f"e{i}.dscb.akamaiedge.net", i) for i in range(50)]
        assert DnsTunnelingRule().analyze(records) == []

    def test_near_miss_long_but_low_entropy(self):
        records = [dns(i, "10.0.5.23", f"{'a' * 35}{i:03d}.example.com", i) for i in range(50)]
        assert DnsTunnelingRule().analyze(records) == []

    def test_allowlisted_parent_domain(self):
        assert DnsTunnelingRule(allowlist=["exfil-tunnel.net"]).analyze(self.queries(25)) == []

    def test_parent_domain_and_entropy_helpers(self):
        assert parent_domain("a.b.example.co.uk") == ("a.b", "example.co.uk")
        assert parent_domain("x.y.example.com") == ("x.y", "example.com")
        assert shannon_entropy("aaaa") == 0
        assert shannon_entropy("abcd") == 2


# ── egress_volume_anomaly ────────────────────────────────────────────────────

def hourly(host, hour, megabytes, n, dst="52.95.110.1"):
    return LogRecord(
        line_number=n, timestamp=(BASE.replace(hour=0) + timedelta(hours=hour, minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        hostname=host, ip_address="10.0.4.2", dest_ip=dst, bytes_out=megabytes * 1_000_000,
    )


class TestEgressVolumeAnomaly:
    @pytest.mark.no_db
    def test_spike_after_stable_baseline_fires_in_one_batch(self):
        records = [hourly("fs-02", h, 20, h) for h in range(8)] + [hourly("fs-02", 8, 900, 99, dst="91.198.174.192")]
        alerts = EgressVolumeAnomalyRule().analyze(records)
        assert len(alerts) == 1
        assert alerts[0].evidence["bytes_out"] == 900_000_000
        assert alerts[0].evidence["top_destinations"][0]["destination"] == "91.198.174.192"

    @pytest.mark.no_db
    def test_near_miss_not_enough_history(self):
        records = [hourly("fs-02", h, 20, h) for h in range(3)] + [hourly("fs-02", 3, 900, 99)]
        assert EgressVolumeAnomalyRule().analyze(records) == []

    @pytest.mark.no_db
    def test_near_miss_normal_variation(self):
        records = [hourly("fs-02", h, 20 + (h % 3) * 5, h) for h in range(12)]
        assert EgressVolumeAnomalyRule().analyze(records) == []

    @pytest.mark.no_db
    def test_internal_destinations_are_not_egress(self):
        records = [hourly("fs-02", h, 20, h) for h in range(8)] + [hourly("fs-02", 8, 900, 99, dst="10.0.9.9")]
        assert EgressVolumeAnomalyRule().analyze(records) == []

    def test_baseline_persists_across_uploads(self, db_session):
        host = f"fs-{uuid4().hex[:6]}"
        rule = EgressVolumeAnomalyRule()
        assert rule.analyze([hourly(host, h, 20, h) for h in range(8)], db_session) == []
        alerts = rule.analyze([hourly(host, 9, 900, 1)], db_session)
        assert len(alerts) == 1
        # The same bucket re-uploaded is not re-evaluated.
        assert rule.analyze([hourly(host, 9, 900, 1)], db_session) == []


# ── threat intel ─────────────────────────────────────────────────────────────

@pytest.mark.no_db
class TestThreatFeedParsing:
    def test_classifies_ips_cidrs_domains_and_rejects_junk(self):
        assert classify_indicator("185.220.101.45") == ("185.220.101.45", "ip")
        assert classify_indicator("45.155.205.0/24") == ("45.155.205.0/24", "cidr")
        assert classify_indicator("45.155.205.7/32") == ("45.155.205.7", "ip")
        assert classify_indicator("*.Evil.COM.") == ("evil.com", "domain")
        assert classify_indicator("https://bad.example.org/path") == ("bad.example.org", "domain")
        assert classify_indicator("0.0.0.0/0") is None
        assert classify_indicator("not an indicator") is None

    def test_parse_feed_handles_comments_and_csv(self):
        indicators, rejected = parse_feed("# header\n1.2.3.4 ; note\n5.6.7.0/24,Spamhaus\nevil.com\n???\n")
        assert dict(indicators) == {"1.2.3.4": "ip", "5.6.7.0/24": "cidr", "evil.com": "domain"}
        assert rejected == 1


class TestThreatIntelMatchRule:
    def test_matches_dest_ip_cidr_and_parent_domain(self, db_session):
        source = f"feed-{uuid4().hex[:6]}"
        import_feed(db_session, source=source, content="45.155.205.0/24\nbadactor-c2.com\n", replace=True, description=None, created_by=None)
        records = [
            flow(1, "10.0.3.30", "45.155.205.99", 443, 0, host="ws-130"),
            LogRecord(line_number=2, timestamp=ts(5), ip_address="10.0.5.40", dns_query="cdn.badactor-c2.com", process="dnsmasq", hostname="dns01"),
            flow(3, "10.0.3.31", "8.8.8.8", 53, 10, host="ws-131"),
        ]
        alerts = {a.entity_id: a for a in ThreatIntelMatchRule().analyze(records, db_session)}
        assert set(alerts) == {"ws-130", "10.0.5.40"}
        assert alerts["ws-130"].evidence["indicator"] == "45.155.205.0/24"
        assert alerts["10.0.5.40"].evidence["direction"] == "dns"

    def test_allowlist_suppresses_indicator(self, db_session):
        import_feed(db_session, source=f"feed-{uuid4().hex[:6]}", content="185.220.101.45\n", replace=True, description=None, created_by=None)
        record = flow(1, "10.0.2.44", "185.220.101.45", 443, 0)
        assert ThreatIntelMatchRule(allowlist=["185.220.101.45"]).analyze([record], db_session) == []

    @pytest.mark.no_db
    def test_without_database_matches_nothing(self):
        assert ThreatIntelMatchRule().analyze([flow(1, "10.0.2.44", "185.220.101.45", 443, 0)]) == []
