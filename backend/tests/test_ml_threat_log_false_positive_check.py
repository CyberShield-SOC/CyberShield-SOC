"""
Follow-up to test_ml_threat_log_attack_injection.py: measures false
positives under *realistic* normal traffic, not just the narrow 3-fixed-
destination traffic that test used.

Motivation: in the original attack-injection test, every normal IP only
ever talked to the same 3 destinations on ports 443/80, so it never
exercised the novelty/rarity features at all for normal traffic -- a real
user who happens to visit a site for the first time looks, feature-wise,
identical to the start of a port scan or an exfil attempt (both score as
"never seen this destination before"). This file measures how often that
actually produces a false positive, across four levels of how often normal
traffic contains a genuinely new destination (0%, 5%, 15%, 30% of buckets).

This measures only -- it does not change score_threshold, the feature set,
or shadow_mode. shadow_mode stays at its default (True) throughout, same
footing as test_ml_threat_log_attack_injection.py. The existing test file
is untouched; this one duplicates the small set of helpers it needs
(upload_csv, the admin-auth fixture, the three attack-row generators) to
stay self-contained rather than import across test modules.

Only one claim is asserted as a stability guarantee: the three *loud*
attacks must still be detected at 0% ambient novelty (the same population
shape the original test already covers). Every other number -- false-
positive rate, subtle-attack detection rate, ROC-AUC, which normal
behaviors drove the false positives -- is a measurement, reported to
ml_experiments/reports/threat_log_false_positive_check.txt, not a pass/fail
gate, so this test can't go flaky on the inherent run-to-run variance of a
Monte Carlo population.
"""

from __future__ import annotations

import csv
import io
import random
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sklearn.metrics import roc_auc_score
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
NORMAL_PORTS = {443: "HTTPS", 80: "HTTP"}

# The provisional threshold suggested by test_ml_threat_log_attack_injection.py.
# Not changed here -- this file only measures against it.
CURRENT_THRESHOLD = -0.12

NOVELTY_LEVELS = (0.0, 0.05, 0.15, 0.30)
N_NORMAL_IPS = 30
SPIKE_PROB = 0.08  # constant across novelty levels -- an independent confound, not what's being swept
DENY_RATE_RANGE = (0.05, 0.20)  # per-IP baseline, constant across novelty levels

# Three address pools standing in for "the organization's traffic":
# CORE_POOL: the stable, shared "regular sites" normal IPs draw their own
# personal 2-3 destinations from (so IPs naturally overlap on common ones).
# POPULAR_POOL: other legitimate destinations that are new to one IP the
# first time it visits but are not globally rare (a popular external site).
# A disjoint range (198.18.0.0/15, RFC 2544 benchmarking space) backs truly
# rare, seen-once destinations so novel traffic isn't all equally common.
CORE_POOL = [f"198.51.100.{i}" for i in range(10, 30)]
POPULAR_POOL = [f"192.0.2.{i}" for i in range(10, 20)]

REPORT_PATH = Path(__file__).resolve().parents[2] / "ml_experiments" / "reports" / "threat_log_false_positive_check.txt"


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
        username=f"tl_fp_admin_{suffix}",
        email=f"tl_fp_admin_{suffix}@example.test",
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


# --- The three attack-row generators, identical to
# test_ml_threat_log_attack_injection.py -- duplicated rather than
# cross-imported so this file stays self-contained. Keep these in sync with
# that file if the attack shapes ever change there. ---------------------

def port_scan_rows(source_ip: str, hour: int, *, dest: str, num_ports: int) -> list[dict]:
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


def big_transfer_rows(source_ip: str, hour: int, *, dest: str, bytes_out: int, count: int) -> list[dict]:
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


def deny_burst_rows(source_ip: str, hour: int, *, dest: str, count: int, deny_fraction: float) -> list[dict]:
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


# --- Realistic normal-traffic generator -----------------------------------

class RarePool:
    """True long-tail destinations: each one effectively seen once across
    the whole run, in a block disjoint from CORE_POOL/POPULAR_POOL and from
    the attack generators' fixed destinations (203.0.113.x), so a "rare"
    draw can never accidentally collide with either."""

    def __init__(self):
        self._counter = 0

    def next(self) -> str:
        self._counter += 1
        third = (self._counter // 254) % 50
        fourth = (self._counter % 254) + 1
        return f"198.18.{third}.{fourth}"


def make_profile(rng: random.Random) -> dict:
    core = rng.sample(CORE_POOL, k=rng.randint(2, 3))
    return {"core": core, "deny_rate": rng.uniform(*DENY_RATE_RANGE), "seen": set(core)}


def realistic_bucket_rows(
    rng: random.Random, rare_pool: RarePool, profile: dict, source_ip: str, hour: int, novelty_level: float,
) -> tuple[list[dict], dict]:
    """One hour of realistic traffic for one normal IP: mostly its own core
    destinations, occasionally (at `novelty_level` probability) 1-3
    destinations it has never visited before, and occasionally (constant
    SPIKE_PROB, independent of novelty_level) one legitimate large download
    from a known/popular destination. Returns (rows, ground-truth metadata)
    -- the metadata is for this test's own false-positive attribution, not
    anything the rule itself sees."""

    novel_this_bucket = rng.random() < novelty_level
    new_dests: list[str] = []
    if novel_this_bucket:
        for _ in range(rng.randint(1, 3)):
            candidate = rng.choice(POPULAR_POOL) if rng.random() < 0.7 else rare_pool.next()
            if candidate not in profile["seen"]:
                new_dests.append(candidate)
                profile["seen"].add(candidate)

    rows = []
    for i in range(rng.randint(3, 6)):
        dest = rng.choice(new_dests) if new_dests and rng.random() < 0.5 else rng.choice(profile["core"])
        port = rng.choice(list(NORMAL_PORTS))
        rows.append({
            "timestamp": _ts(hour, minute=rng.randint(0, 59), second=i),
            "ip_address": source_ip,
            "dest_ip": dest,
            "protocol": NORMAL_PORTS[port],
            "port": port,
            "bytes_out": rng.randint(2_000, 20_000),
            "status": "DENIED" if rng.random() < profile["deny_rate"] else "ALLOWED",
        })

    had_spike = rng.random() < SPIKE_PROB
    if had_spike:
        spike_dest = rng.choice(profile["core"] + POPULAR_POOL)
        rows.append({
            "timestamp": _ts(hour, minute=59, second=59),
            "ip_address": source_ip,
            "dest_ip": spike_dest,
            "protocol": "HTTPS",
            "port": 443,
            "bytes_out": rng.randint(100_000_000, 300_000_000),
            "status": "ALLOWED",
        })

    denied = sum(1 for r in rows if r["status"] == "DENIED")
    meta = {
        "had_novel_dest": bool(new_dests),
        "new_dest_count": len(new_dests),
        "had_spike": had_spike,
        "connection_count": len(rows),
        "observed_deny_rate": (denied / len(rows)) if rows else 0.0,
        "assigned_deny_rate": profile["deny_rate"],
    }
    return rows, meta


def run_scenario(db_session, monkeypatch, *, novelty_level: float, subnet: int, seed: int = 2024) -> dict:
    """Full real-upload-path scenario for one novelty level: 6 hours of
    realistic history -> train+activate a real model -> inject the 6
    attacks (loud+subtle) alongside 30 continuing normal IPs -> read back
    scores. Returns a dict of everything the report needs."""

    feature_set = f"pytest-fp-{subnet}-{uuid4().hex[:6]}"
    monkeypatch.setattr("app.detection.rules.behavioral_anomaly_threat_log.FEATURE_SET", feature_set)
    monkeypatch.setattr("app.ml.train_threat_detection.FEATURE_SET", feature_set)

    rng = random.Random(seed)
    rare_pool = RarePool()
    normal_ips = [f"10.{subnet}.1.{i}" for i in range(1, N_NORMAL_IPS + 1)]
    attack_ips = {
        "port_scan (loud, 25 new ports)": f"10.{subnet}.2.1",
        "big_transfer (loud, 800MB new dest)": f"10.{subnet}.2.2",
        "deny_burst (loud, 100% denied)": f"10.{subnet}.2.3",
        "port_scan (subtle, 5 new ports)": f"10.{subnet}.2.4",
        "big_transfer (subtle, 50MB new dest)": f"10.{subnet}.2.5",
        "deny_burst (subtle, 40% denied)": f"10.{subnet}.2.6",
    }
    all_ips = normal_ips + list(attack_ips.values())
    profiles = {ip: make_profile(rng) for ip in all_ips}

    # --- Upload #1: 6 hours of realistic history for every IP, normal and
    # attack alike, at this run's novelty level.
    history_rows = []
    bucket_count = 0
    novel_bucket_count = 0
    for hour in range(6):
        for ip in all_ips:
            rows, meta = realistic_bucket_rows(rng, rare_pool, profiles[ip], ip, hour, novelty_level)
            history_rows += rows
            bucket_count += 1
            novel_bucket_count += int(meta["had_novel_dest"])

    history_response = upload_csv(history_rows)
    assert history_response.status_code == 200

    snapshot_count = len(list_feature_snapshots(db_session, feature_set=feature_set, entity_type="source_ip"))
    assert snapshot_count >= 50

    from app.ml.train_threat_detection import train
    model_row = train(db_session, min_samples=50, random_state=42)
    db_session.commit()
    assert model_row.is_active

    # --- Upload #2: the 30 normal IPs continue realistically for one more
    # hour; the 6 attack IPs get their injected bucket instead.
    test_rows = []
    injection_meta: dict[str, dict] = {}
    for ip in normal_ips:
        rows, meta = realistic_bucket_rows(rng, rare_pool, profiles[ip], ip, hour=6, novelty_level=novelty_level)
        test_rows += rows
        injection_meta[ip] = meta
        bucket_count += 1
        novel_bucket_count += int(meta["had_novel_dest"])

    test_rows += port_scan_rows(attack_ips["port_scan (loud, 25 new ports)"], hour=6, dest=CORE_POOL[0], num_ports=25)
    test_rows += big_transfer_rows(
        attack_ips["big_transfer (loud, 800MB new dest)"], hour=6, dest="203.0.113.77", bytes_out=800_000_000, count=2,
    )
    test_rows += deny_burst_rows(
        attack_ips["deny_burst (loud, 100% denied)"], hour=6, dest=CORE_POOL[0], count=20, deny_fraction=1.0,
    )
    test_rows += port_scan_rows(attack_ips["port_scan (subtle, 5 new ports)"], hour=6, dest=CORE_POOL[1], num_ports=5)
    test_rows += big_transfer_rows(
        attack_ips["big_transfer (subtle, 50MB new dest)"], hour=6, dest="203.0.113.88", bytes_out=50_000_000, count=1,
    )
    test_rows += deny_burst_rows(
        attack_ips["deny_burst (subtle, 40% denied)"], hour=6, dest=CORE_POOL[1], count=20, deny_fraction=0.4,
    )

    test_response = upload_csv(test_rows)
    assert test_response.status_code == 200

    all_snapshots = list_feature_snapshots(db_session, feature_set=feature_set, entity_type="source_ip")
    latest_by_ip = {}
    for snapshot in all_snapshots:
        latest_by_ip[snapshot.entity_id] = snapshot

    normal_scores = {ip: latest_by_ip[ip].score for ip in normal_ips}
    attack_scores = {name: latest_by_ip[ip].score for name, ip in attack_ips.items()}
    loud_scores = {k: v for k, v in attack_scores.items() if "loud" in k}
    subtle_scores = {k: v for k, v in attack_scores.items() if "subtle" in k}

    flagged_normal_ips = [ip for ip, score in normal_scores.items() if score < CURRENT_THRESHOLD]
    cause_tally = Counter()
    for ip in flagged_normal_ips:
        meta = injection_meta[ip]
        if meta["had_novel_dest"]:
            cause_tally["new_destination"] += 1
        if meta["had_spike"]:
            cause_tally["volume_spike"] += 1
        if meta["assigned_deny_rate"] > 0.15:
            cause_tally["elevated_deny_rate"] += 1
        if not (meta["had_novel_dest"] or meta["had_spike"] or meta["assigned_deny_rate"] > 0.15):
            cause_tally["no_obvious_cause"] += 1

    labels = [0] * len(normal_scores) + [1] * len(attack_scores)
    anomaly_scores = [-s for s in normal_scores.values()] + [-s for s in attack_scores.values()]
    auc = roc_auc_score(labels, anomaly_scores) if len(set(labels)) > 1 else float("nan")

    return {
        "novelty_level": novelty_level,
        "actual_novel_bucket_fraction": novel_bucket_count / bucket_count,
        "normal_scores": normal_scores,
        "attack_scores": attack_scores,
        "loud_scores": loud_scores,
        "subtle_scores": subtle_scores,
        "fp_rate": len(flagged_normal_ips) / len(normal_scores),
        "flagged_normal_ips": flagged_normal_ips,
        "cause_tally": cause_tally,
        "loud_detection_rate": sum(1 for s in loud_scores.values() if s < CURRENT_THRESHOLD) / len(loud_scores),
        "subtle_detection_rate": sum(1 for s in subtle_scores.values() if s < CURRENT_THRESHOLD) / len(subtle_scores),
        "normal_min": min(normal_scores.values()),
        "normal_max": max(normal_scores.values()),
        "attack_min": min(attack_scores.values()),
        "attack_max": max(attack_scores.values()),
        "roc_auc": auc,
    }


def _format_report(results: list[dict]) -> str:
    lines = []
    lines.append("False-positive check for behavioral_anomaly_threat_log under realistic normal traffic")
    lines.append("=" * 88)
    lines.append(f"provisional score_threshold used throughout: {CURRENT_THRESHOLD}")
    lines.append(f"normal IPs per run: {N_NORMAL_IPS}  |  attack IPs per run: 6 (3 loud + 3 subtle)")
    lines.append("")

    for r in results:
        lines.append(
            f"--- novelty_level={r['novelty_level']:.0%} "
            f"(actual novel-bucket fraction observed: {r['actual_novel_bucket_fraction']:.1%}) ---"
        )
        lines.append(f"false-positive rate @ threshold: {r['fp_rate']:.1%} ({len(r['flagged_normal_ips'])}/{N_NORMAL_IPS})")
        lines.append(f"loud-attack detection rate @ threshold:   {r['loud_detection_rate']:.0%}")
        lines.append(f"subtle-attack detection rate @ threshold: {r['subtle_detection_rate']:.0%}")
        lines.append(f"normal scores:  min={r['normal_min']:.4f}  max={r['normal_max']:.4f}")
        lines.append(f"attack scores:  min={r['attack_min']:.4f}  max={r['attack_max']:.4f}")
        lines.append(f"ROC-AUC (all 6 attacks vs. all {N_NORMAL_IPS} normals): {r['roc_auc']:.4f}")
        if r["flagged_normal_ips"]:
            lines.append(f"false positives caused by (counts, a flagged IP can have >1 cause): {dict(r['cause_tally'])}")
        else:
            lines.append("false positives caused by: n/a (none flagged)")
        lines.append("")

    lines.append("--- summary across novelty levels ---")
    header = f"{'novelty':>9} {'fp_rate':>9} {'loud_det':>9} {'subtle_det':>11} {'roc_auc':>8} {'normal_max':>11} {'attack_min':>11}"
    lines.append(header)
    for r in results:
        lines.append(
            f"{r['novelty_level']:>8.0%} {r['fp_rate']:>9.1%} {r['loud_detection_rate']:>9.0%} "
            f"{r['subtle_detection_rate']:>11.0%} {r['roc_auc']:>8.4f} {r['normal_max']:>11.4f} {r['attack_min']:>11.4f}"
        )

    return "\n".join(lines) + "\n"


class TestThreatLogFalsePositiveCheck:
    def test_false_positive_rate_across_novelty_levels(self, db_session, monkeypatch):
        results = [
            run_scenario(db_session, monkeypatch, novelty_level=level, subnet=40 + i)
            for i, level in enumerate(NOVELTY_LEVELS)
        ]

        report = _format_report(results)
        print("\n" + report)

        REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
        REPORT_PATH.write_text(report, encoding="utf-8")

        # The only claim treated as a stability guarantee: with zero ambient
        # novelty (the population shape test_ml_threat_log_attack_injection.py
        # already covers), the three loud attacks must still be caught.
        zero_novelty = results[0]
        assert zero_novelty["novelty_level"] == 0.0
        assert zero_novelty["loud_detection_rate"] == 1.0, (
            f"expected all 3 loud attacks detected at 0% ambient novelty; "
            f"loud_scores={zero_novelty['loud_scores']}"
        )
