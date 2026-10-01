"""
Offline check: does the production `threat_log` feature set (see
backend/app/ml/features_threat_log.py) hold up against the same
cybersecurity_threat_detection_logs.csv that justified building the pilot
in the first place (see reports/threat_detection_logs.txt, ROC-AUC 0.72)?

That 0.72 baseline was per-row, one-hot-encoded (protocol/action/user_agent
as dummy columns, frequency-encoded IPs/paths) -- a feature shape this
pipeline's fixed feature_names contract can't use in production (see
features_threat_log.py's docstring). This script re-derives the same rows
into (source_ip, hourly-bucket) groups, walked in chronological order per
source IP so the rarity/novelty features are computed against each source
IP's history *strictly before* that bucket (via the real
app.ml.features_threat_log.empty_history/update_history functions -- the
exact functions production uses, not a re-implementation), labels each
bucket "anomalous" if any row in it was non-benign, and runs the identical
IsolationForest methodology run_one() uses in train_isolation_forest.py
(same split, same scaler, same contamination calibration, same
random_state) so only the feature design differs between reports.

A labeling caveat worth knowing before reading these numbers: "any row in
this bucket is non-benign" correlates with bucket size on its own --
bucket size (connection_count) alone reaches ROC-AUC ~0.66 against this
label with zero behavioral signal (ml_experiments/reports/
threat_detection_logs_label_fairness_check.txt has the full breakdown).
That confound sits under every number below equally (every feature set
compared here includes connection_count), so the *relative* comparison
between feature sets stays meaningful, but none of these absolute ROC-AUC
numbers should be read as "this much genuine behavioral signal".

Run:
    backend/.venv/Scripts/python.exe ml_experiments/eval_production_threat_log_features.py
"""

from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT.parent / "Dataset for anamoly detection"
REPORTS_DIR = ROOT / "reports"
RANDOM_STATE = 42
TEST_SIZE = 0.2
BUCKET_FREQ = "h"

sys.path.insert(0, str(ROOT.parent / "backend"))
from app.ml.features_threat_log import (  # noqa: E402
    FEATURE_NAMES,
    empty_history,
    threat_log_features,
    update_history,
)

_DENIED_ACTIONS = frozenset({"blocked", "denied", "dropped", "rejected"})

# The original 5-feature design (no rarity/novelty/entropy) is just the
# first 5 columns of the current FEATURE_NAMES -- a column slice of the same
# bucket data, not a separately computed feature set, so the 3-way
# comparison can't drift out of sync with the real module by hand-copying
# an old feature list here.
BASELINE_5_FEATURES = ("log_bytes_total", "connection_count", "distinct_destinations", "distinct_ports", "deny_rate")


def load_raw_sample(sample_rows: int = 300_000, total_rows: int = 6_000_000) -> pd.DataFrame:
    """Identical sampling to train_isolation_forest.py's load_threat_detection_logs
    (same chunksize, same frac, same rng seed) so both evaluations see the same
    rows -- only the feature engineering differs downstream."""

    path = DATA_DIR / "cybersecurity_threat_detection_logs.csv"
    frac = min(1.0, sample_rows / total_rows)
    rng = np.random.default_rng(RANDOM_STATE)
    chunks = []
    for chunk in pd.read_csv(path, chunksize=200_000):
        if frac < 1.0:
            mask = rng.random(len(chunk)) < frac
            chunk = chunk[mask]
        chunks.append(chunk)
    return pd.concat(chunks, ignore_index=True)


def build_bucket_dataset(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.Series]:
    """Group rows into (source_ip, hourly-bucket) the same way
    BehavioralAnomalyThreatLogRule does, then walk each source IP's buckets
    in chronological order maintaining a running history exactly like the
    rule does, scoring each bucket against history as of strictly before it.

    `port_counts` stays empty for every bucket -- this dataset has no port
    column, same as any real log source whose parser never populates
    LogRecord.port, which is exactly what this pilot has to cope with in
    practice (the port-based features correctly come out as 0/neutral
    rather than crashing or being silently wrong)."""

    ts = pd.to_datetime(df["timestamp"], utc=True)
    bucket_ts = ts.dt.floor(BUCKET_FREQ)
    is_denied = df["action"].astype(str).str.lower().isin(_DENIED_ACTIONS)
    is_anomalous = df["threat_label"].astype(str) != "benign"

    per_row = pd.DataFrame({
        "source_ip": df["source_ip"],
        "dest_ip": df["dest_ip"],
        "protocol": df["protocol"].astype(str),
        "bytes_transferred": df["bytes_transferred"].astype(float),
        "denied": is_denied,
        "anomalous": is_anomalous,
        "bucket_ts": bucket_ts,
    })

    bucket_rows = []
    for (source_ip, bucket_ts_value), group in per_row.groupby(["source_ip", "bucket_ts"]):
        bucket_rows.append({
            "source_ip": source_ip,
            "bucket_ts": bucket_ts_value,
            "bytes_total": int(group["bytes_transferred"].sum()),
            "connection_count": len(group),
            "denied_count": int(group["denied"].sum()),
            "dest_counts": Counter(group["dest_ip"]),
            "protocol_counts": Counter(group["protocol"]),
            "label": int(group["anomalous"].any()),
        })

    bucket_rows.sort(key=lambda r: (r["source_ip"], r["bucket_ts"]))

    rows = []
    labels = []
    histories: dict[str, dict] = {}
    for r in bucket_rows:
        history = histories.setdefault(r["source_ip"], empty_history())
        features = threat_log_features(
            bytes_total=r["bytes_total"], connection_count=r["connection_count"], denied_count=r["denied_count"],
            dest_counts=r["dest_counts"], port_counts={}, protocol_counts=r["protocol_counts"], history=history,
        )
        rows.append(features)
        labels.append(r["label"])
        histories[r["source_ip"]] = update_history(
            history, dest_counts=r["dest_counts"], port_counts={}, protocol_counts=r["protocol_counts"],
            connection_count=r["connection_count"],
        )

    X = pd.DataFrame(rows, columns=list(FEATURE_NAMES))
    y = pd.Series(labels, name="anomalous")
    return X, y


def evaluate(X: pd.DataFrame, y: pd.Series, *, label: str) -> str:
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y
    )

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    contamination = float(np.clip(y_train.mean(), 0.001, 0.5))
    model = IsolationForest(
        n_estimators=200,
        max_samples=min(256, len(X_train)),
        contamination=contamination,
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    model.fit(X_train_scaled)

    raw_pred = model.predict(X_test_scaled)  # 1 = normal, -1 = anomaly
    y_pred = (raw_pred == -1).astype(int)
    anomaly_score = -model.decision_function(X_test_scaled)

    report = classification_report(y_test, y_pred, target_names=["normal", "anomaly"], zero_division=0)
    cm = confusion_matrix(y_test, y_pred)
    try:
        auc = roc_auc_score(y_test, anomaly_score)
    except ValueError:
        auc = float("nan")

    summary = (
        f"dataset: {label}\n"
        f"rows: {len(X)}  features: {X.shape[1]}  contamination: {contamination:.4f}\n"
        f"ROC-AUC (anomaly score vs. true label): {auc:.4f}\n\n"
        f"confusion matrix [rows=true, cols=pred] (normal, anomaly):\n{cm}\n\n"
        f"{report}"
    )
    return summary


def main() -> int:
    print("Loading raw sample (same rows as the one-hot baseline)...")
    raw = load_raw_sample()
    print(f"{len(raw)} raw rows loaded")

    print("Building (source_ip, hourly-bucket) features chronologically via the real production functions...")
    X_full, y = build_bucket_dataset(raw)
    print(f"{len(X_full)} buckets, anomaly rate {y.mean():.4f}")

    summary_5 = evaluate(
        X_full[list(BASELINE_5_FEATURES)], y,
        label="threat_detection_logs (production threat_log features, 5-feature, bucketed)",
    )
    print("\n" + summary_5)
    (REPORTS_DIR / "threat_detection_logs_production_features.txt").write_text(summary_5, encoding="utf-8")

    summary_12 = evaluate(
        X_full, y,
        label="threat_detection_logs (production threat_log features, 12-feature w/ rarity+novelty+entropy, bucketed)",
    )
    print("\n" + summary_12)
    (REPORTS_DIR / "threat_detection_logs_production_features_rarity.txt").write_text(summary_12, encoding="utf-8")

    baseline_path = REPORTS_DIR / "threat_detection_logs.txt"
    if baseline_path.exists():
        print("\n" + "=" * 70)
        print("BASELINE (one-hot, per-row) for comparison:")
        print("=" * 70)
        print(baseline_path.read_text(encoding="utf-8"))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
