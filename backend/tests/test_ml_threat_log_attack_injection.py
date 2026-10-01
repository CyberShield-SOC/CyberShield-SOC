"""
Attack-injection test for IsolationForest pilot #3 (behavioral_anomaly_threat_log).

The offline checks in ml_experiments/ (see
ml_experiments/reports/threat_detection_logs_label_fairness_check.txt) found
the one CSV dataset available for this pilot has a labeling artifact that
makes it unsuitable for judging whether these features actually catch
anything -- bucket size alone predicts the label about as well as the real
feature set does. That rules out the Kaggle CSV as a signal check.

This replaces it with a synthetic ground truth instead: build an
established "normal" traffic history for a population of source IPs
through the real /upload endpoint (the same code path a real deployment
uses -- CSV parsing, normalize.py, the detection engine, this rule), train
a real model on the resulting snapshots, then inject three known attack
shapes into a follow-up upload for three of those same IPs and read back
the IsolationForest scores the rule actually produced:

  1. a port scan -- one source IP hitting one known destination across
     many never-before-seen ports in one hour
  2. a large outbound transfer to a brand-new destination
  3. a burst of denied connections -- deny rate far above that IP's own
     history

Each attack IP has the *same* established normal history as the ordinary
IPs up to the point of injection, so a lower score can only be attributed
to the injected bucket itself, not to the IP looking unusual from the
start. shadow_mode stays at its default (True) throughout -- this test
reads persisted snapshot scores directly, which the rule always records
once a model is active, regardless of shadow_mode (see
app/ml/pipeline.py's record_and_score); it never flips shadow_mode off or
asserts on alerts.
"""

from __future__ import annotations

import csv
import io
import random
import sys
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.main import app
from app.models.role import Role
from app.models.user import User
from app.repositories.ml_repository import list_feature_snapshots
from app.security import current_user

client = TestClient(app)

BASE = datetime(2026, 1, 5, tzinfo=timezone.utc)
CSV_COLUMNS = ("timestamp", "ip_address", "dest_ip", "protocol", "port", "bytes_out", "status")

# Shared pool of destinations/ports every "normal" IP's history is built
# from, so established history naturally overlaps across IPs the way real
# traffic to a handful of common services would.
NORMAL_DESTS = ["198.51.100.10", "198.51.100.11", "198.51.100.12"]
NORMAL_PORTS = {443: "HTTPS", 80: "HTTP"}


@pytest.fixture(autouse=True)
def authenticated_admin(db_session):
    admin_role = db_session.scalar(select(Role).where(Role.name == "Admin"))
    if admin_role is None:
        admin_role = Role(name="Admin", description="Administrator")
        db_session.add(admin_role)
        db_session.flush()

    suffix = uuid4().hex
    admin_user = User(
        role_id=admin_role.id,
        username=f"threatlog_admin_{suffix}",
        email=f"threatlog_admin_{suffix}@example.test",
        password_hash="not-used",
        is_active=True,
    )
    db_session.add(admin_user)
    db_session.commit()

    app.dependency_overrides[current_user] = lambda: admin_user
    yield
    app.dependency_overrides.pop(current_user, None)


def upload_csv(rows: list[dict], name: str = "flow.csv"):
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=CSV_COLUMNS)
    writer.writeheader()
    writer.writerows(rows)
    content = buffer.getvalue().encode()
    return client.post("/upload", files={"logfile": (name, io.BytesIO(content), "text/csv")})


def _ts(hour: int, minute: int, second: int = 0) -> str:
    return BASE.replace(hour=hour, minute=minute, second=second).strftime("%Y-%m-%dT%H:%M:%SZ")


def normal_bucket_rows(rng: random.Random, source_ip: str, hour: int) -> list[dict]:
    """A realistic hour of unremarkable traffic: a handful of connections to
    the shared destination/port pool, mostly allowed, modest byte counts --
    the same kind of jittered-but-narrow distribution
    test_ml_egress_volume.py's own `_train_quiet_host_model` uses, so
    IsolationForest gets real variance to split on instead of duplicate
    points collapsing every score together."""

    rows = []
    for i in range(rng.randint(3, 6)):
        port = rng.choice(list(NORMAL_PORTS))
        rows.append({
            "timestamp": _ts(hour, minute=rng.randint(0, 59), second=i),
            "ip_address": source_ip,
            "dest_ip": rng.choice(NORMAL_DESTS),
            "protocol": NORMAL_PORTS[port],
            "port": port,
            "bytes_out": rng.randint(2_000, 20_000),
            "status": "DENIED" if rng.random() < 0.1 else "ALLOWED",
        })
    return rows


def port_scan_rows(source_ip: str, hour: int, *, dest: str = NORMAL_DESTS[0], num_ports: int = 25) -> list[dict]:
    """One source IP hitting a known destination across many ports it has
    never used before in a single hour -- distinct_ports/port_entropy/
    new_port_rate should all spike relative to this IP's own 2-port history."""

    return [
        {
            "timestamp": _ts(hour, minute=i % 60, second=0),
            "ip_address": source_ip,
            "dest_ip": dest,
            "protocol": "TCP",
            "port": 20_000 + i,
            "bytes_out": 100,
            "status": "ALLOWED",
        }
        for i in range(num_ports)
    ]


def big_transfer_rows(
    source_ip: str, hour: int, *, dest: str = "203.0.113.77", bytes_out: int = 800_000_000, count: int = 2,
) -> list[dict]:
    """A small number of connections carrying a huge byte count to a
    destination this source IP has never talked to before -- log_bytes_total
    and dest_rarity/new_destination_rate should spike; port/protocol stay
    inside this IP's known history so only the destination is novel."""

    return [
        {
            "timestamp": _ts(hour, minute=5 * i, second=0),
            "ip_address": source_ip,
            "dest_ip": dest,
            "protocol": "HTTPS",
            "port": 443,
            "bytes_out": bytes_out,
            "status": "ALLOWED",
        }
        for i in range(count)
    ]


def deny_burst_rows(
    source_ip: str, hour: int, *, dest: str = NORMAL_DESTS[0], count: int = 20, deny_fraction: float = 1.0,
) -> list[dict]:
    """A burst of connections to an already-known destination/port, a
    `deny_fraction` share of them denied -- deny_rate should spike above
    this IP's usual ~10% baseline while destination/port rarity stay
    unremarkable. deny_fraction=1.0 (the loud variant) denies every
    connection; a lower fraction is the "~40% denied" subtle variant."""

    denied_count = round(count * deny_fraction)
    return [
        {
            "timestamp": _ts(hour, minute=i % 60, second=0),
            "ip_address": source_ip,
            "dest_ip": dest,
            "protocol": "HTTPS",
            "port": 443,
            "bytes_out": 500,
            "status": "DENIED" if i < denied_count else "ALLOWED",
        }
        for i in range(count)
    ]


class TestThreatLogAttackInjection:
    def test_injected_attacks_score_more_anomalous_than_normal_traffic(self, db_session, monkeypatch):
        feature_set = f"pytest-{uuid4().hex[:8]}"
        monkeypatch.setattr("app.detection.rules.behavioral_anomaly_threat_log.FEATURE_SET", feature_set)
        monkeypatch.setattr("app.ml.train_threat_detection.FEATURE_SET", feature_set)

        rng = random.Random(7)
        normal_ips = [f"10.1.0.{i}" for i in range(1, 13)]  # 12 ordinary IPs, all scored at injection time
        attack_ips = {
            "port_scan (loud, 25 new ports)": "10.2.0.1",
            "big_transfer (loud, 800MB new dest)": "10.2.0.2",
            "deny_burst (loud, 100% denied)": "10.2.0.3",
            "port_scan (subtle, 5 new ports)": "10.2.0.4",
            "big_transfer (subtle, 50MB new dest)": "10.2.0.5",
            "deny_burst (subtle, 40% denied)": "10.2.0.6",
        }

        # --- Upload #1: establish 6 hours of ordinary history for every IP,
        # attack IPs included -- they must look exactly like any other IP
        # up to the point of injection.
        history_rows = []
        for source_ip in normal_ips + list(attack_ips.values()):
            for hour in range(6):
                history_rows += normal_bucket_rows(rng, source_ip, hour)

        history_response = upload_csv(history_rows)
        assert history_response.status_code == 200

        snapshot_count = len(
            list_feature_snapshots(db_session, feature_set=feature_set, entity_type="source_ip")
        )
        assert snapshot_count >= 50  # MIN_SAMPLES for train_threat_detection

        from app.ml.train_threat_detection import train
        model_row = train(db_session, min_samples=50, random_state=42)
        db_session.commit()
        assert model_row.is_active

        # --- Upload #2: every normal IP continues its usual pattern for one
        # more hour; the six attack IPs each get one injected bucket instead
        # -- three "loud" (original) attacks and three "subtle" variants
        # turned down toward the edge of what might still look ordinary.
        test_rows = []
        for source_ip in normal_ips:
            test_rows += normal_bucket_rows(rng, source_ip, hour=6)
        test_rows += port_scan_rows(attack_ips["port_scan (loud, 25 new ports)"], hour=6, num_ports=25)
        test_rows += big_transfer_rows(attack_ips["big_transfer (loud, 800MB new dest)"], hour=6, bytes_out=800_000_000)
        test_rows += deny_burst_rows(attack_ips["deny_burst (loud, 100% denied)"], hour=6, deny_fraction=1.0)
        test_rows += port_scan_rows(
            attack_ips["port_scan (subtle, 5 new ports)"], hour=6, dest=NORMAL_DESTS[1], num_ports=5,
        )
        test_rows += big_transfer_rows(
            attack_ips["big_transfer (subtle, 50MB new dest)"], hour=6,
            dest="203.0.113.88", bytes_out=50_000_000, count=1,
        )
        test_rows += deny_burst_rows(
            attack_ips["deny_burst (subtle, 40% denied)"], hour=6, deny_fraction=0.4,
        )

        test_response = upload_csv(test_rows)
        assert test_response.status_code == 200

        all_snapshots = list_feature_snapshots(db_session, feature_set=feature_set, entity_type="source_ip")
        latest_by_ip = {}
        for snapshot in all_snapshots:
            latest_by_ip[snapshot.entity_id] = snapshot  # oldest-first order, so last write wins

        normal_scores = {ip: latest_by_ip[ip].score for ip in normal_ips}
        attack_scores = {name: latest_by_ip[ip].score for name, ip in attack_ips.items()}
        loud_scores = {k: v for k, v in attack_scores.items() if "loud" in k}
        subtle_scores = {k: v for k, v in attack_scores.items() if "subtle" in k}

        assert all(score is not None for score in normal_scores.values())
        assert all(score is not None for score in attack_scores.values())

        print("\n--- full score table (lower = more anomalous) ---")
        for label, score in sorted({**{f"normal {ip}": s for ip, s in normal_scores.items()}, **attack_scores}.items(), key=lambda kv: kv[1]):
            print(f"{score: .4f}  {label}")

        normal_min, normal_max = min(normal_scores.values()), max(normal_scores.values())
        loud_min, loud_max = min(loud_scores.values()), max(loud_scores.values())
        subtle_min, subtle_max = min(subtle_scores.values()), max(subtle_scores.values())
        attack_min, attack_max = min(attack_scores.values()), max(attack_scores.values())
        print(f"\nnormal (n={len(normal_scores)}):        min={normal_min:.4f}  max={normal_max:.4f}")
        print(f"loud attacks (n={len(loud_scores)}):    min={loud_min:.4f}  max={loud_max:.4f}")
        print(f"subtle attacks (n={len(subtle_scores)}):  min={subtle_min:.4f}  max={subtle_max:.4f}")
        print(f"all attacks (n={len(attack_scores)}):     min={attack_min:.4f}  max={attack_max:.4f}")

        # Midpoint of the two closest points *across* groups (the worst-case
        # normal and the weakest-case attack) -- same idea as this codebase's
        # own test_ml_egress_volume.py::_midpoint_threshold, generalized from
        # one pair of points to a whole population on each side.
        suggested_threshold = (normal_min + attack_max) / 2
        print(
            f"\nsuggested score_threshold (midpoint of worst normal {normal_min:.4f} "
            f"and weakest attack {attack_max:.4f}): {suggested_threshold:.4f}"
        )

        # Lower score = more anomalous (IsolationForest decision_function
        # convention this codebase already uses). Every injected attack --
        # loud AND subtle -- must score below every one of the 12 normal
        # IPs, with no overlap between the two groups at all.
        assert attack_max < normal_min, (
            f"expected every injected attack (loud or subtle) to score below every normal IP; "
            f"attack_range=({attack_min}, {attack_max}) normal_range=({normal_min}, {normal_max})"
        )
