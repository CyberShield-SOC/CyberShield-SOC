"""
Standalone Isolation Forest training over the CSVs in
"Dataset for anamoly detection/".

This is deliberately separate from the app's own ML pipeline
(backend/app/ml/*, which trains on MLFeatureSnapshot rows produced by the
detection rules) -- these five datasets have unrelated, one-off schemas
(raw web logs, pre-engineered network-flow features, KDD-99 records,
synthetic numeric traffic), so each gets its own feature prep here instead
of being forced into that pipeline's fixed login_behavior/egress_volume
feature sets.

Every dataset ships a ground-truth label column. That label is never used
as a training feature (IsolationForest is fit unsupervised, as it would be
in production against unlabeled data) -- it's held out purely to score the
fitted model against on a held-out test split.

Run:
    backend/.venv/Scripts/python.exe ml_experiments/train_isolation_forest.py
    backend/.venv/Scripts/python.exe ml_experiments/train_isolation_forest.py kdd99 synthetic_traffic

With no arguments, trains all datasets. Saves one {model, scaler,
feature_names} joblib bundle per dataset to ml_experiments/models/, and one
metrics report to ml_experiments/reports/.
"""

from __future__ import annotations

import argparse
import io
import os
import sys
import zipfile
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

ROOT = Path(__file__).resolve().parent
# HISTORICAL PROVENANCE: the datasets are NOT in the repository (the old folder
# was ~924 MB, one CSV alone 874 MB). Set CYBERSHIELD_DATASET_DIR to a local
# copy; the default is where the maintainer keeps them, outside the repo and
# outside OneDrive. Results are frozen in reports/. Nothing in backend/tests or
# CI needs these files (see ml_experiments/README.md, "Datasets").
DATA_DIR = Path(os.environ.get("CYBERSHIELD_DATASET_DIR", Path.home() / "datasets" / "cybershield-anomaly-detection"))


def require_datasets() -> None:
    if not DATA_DIR.is_dir():
        raise SystemExit(
            f"Dataset folder not found: {DATA_DIR}\n"
            "This script is historical provenance for the Kaggle-baseline findings in "
            "ml_experiments/README.md; its results are frozen in reports/. It needs local copies "
            "of the datasets, which are not in the repository.\n"
            "Set CYBERSHIELD_DATASET_DIR to a folder that contains them (see ml_experiments/README.md, "
            "'Datasets'). Nothing in backend/tests or CI depends on this folder."
        )
MODELS_DIR = ROOT / "models"
REPORTS_DIR = ROOT / "reports"
RANDOM_STATE = 42
TEST_SIZE = 0.2

MODELS_DIR.mkdir(exist_ok=True)
REPORTS_DIR.mkdir(exist_ok=True)

KDD99_COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land",
    "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in", "num_compromised",
    "root_shell", "su_attempted", "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login", "count",
    "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
    "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label",
]


def _cyclical_time_features(ts: pd.Series) -> pd.DataFrame:
    """hour/day-of-week -> sin/cos pairs, same encoding app/ml/features.py uses,
    so 23:59 and 00:01 land next to each other instead of at opposite ends of a
    raw 0-23 scale. Unparseable timestamps fall back to hour=0/dow=0 rather than
    dropping the row."""

    dt = pd.to_datetime(ts, errors="coerce", utc=True)
    hour = dt.dt.hour.fillna(0) + dt.dt.minute.fillna(0) / 60
    dow = dt.dt.dayofweek.fillna(0)
    return pd.DataFrame(
        {
            "hour_sin": np.sin(2 * np.pi * hour / 24),
            "hour_cos": np.cos(2 * np.pi * hour / 24),
            "dow_sin": np.sin(2 * np.pi * dow / 7),
            "dow_cos": np.cos(2 * np.pi * dow / 7),
        }
    )


def _frequency_encode(col: pd.Series) -> pd.Series:
    """How often this exact value occurs in the column -- cheap stand-in for
    one-hot on high-cardinality identifiers (IPs, paths) where one-hot would
    blow up to thousands of columns."""

    return col.map(col.value_counts()).astype(float)


def _one_hot(df: pd.DataFrame, columns: list[str], max_categories: int = 30) -> pd.DataFrame:
    """One-hot encode, bucketing anything outside the top `max_categories`
    values into '__other__' so a long-tail category doesn't blow up column
    count (KDD-99's `service` has ~70 values)."""

    df = df.copy()
    for c in columns:
        if df[c].nunique() > max_categories:
            top = df[c].value_counts().nlargest(max_categories).index
            df[c] = df[c].where(df[c].isin(top), other="__other__")
    return pd.get_dummies(df, columns=columns, dummy_na=False)


# ---------------------------------------------------------------------------
# Per-dataset loaders. Each returns (X: DataFrame of numeric features, y: 0/1
# Series or None if the dataset has no usable label).
# ---------------------------------------------------------------------------


def load_advanced_cybersecurity() -> tuple[pd.DataFrame, pd.Series]:
    df = pd.read_csv(DATA_DIR / "advanced_cybersecurity_data.csv")
    y = df["Anomaly_Flag"].astype(int)

    time_feats = _cyclical_time_features(df["Timestamp"])
    freq_feats = pd.DataFrame({"ip_frequency": _frequency_encode(df["IP_Address"])})
    categorical = _one_hot(df[["Request_Type", "Status_Code", "User_Agent", "Location"]].astype(str),
                            ["Request_Type", "Status_Code", "User_Agent", "Location"])

    X = pd.concat([time_feats, freq_feats, categorical], axis=1)
    return X, y


def load_embedded_system() -> tuple[pd.DataFrame, pd.Series]:
    df = pd.read_csv(DATA_DIR / "embedded_system_network_security_dataset.csv")
    y = df["label"].astype(int)
    X = df.drop(columns=["label"]).apply(lambda c: c.astype(float))
    return X, y


def load_threat_detection_logs(sample_rows: int = 300_000, total_rows: int = 6_000_000) -> tuple[pd.DataFrame, pd.Series]:
    """874MB / 6M rows -- too big to fit comfortably alongside everything else
    in memory, so this reads it in chunks and keeps a uniform random sample of
    ~`sample_rows` rows rather than just the first N (the file is date-sorted,
    so a plain head() would train on one slice of time only)."""

    path = DATA_DIR / "cybersecurity_threat_detection_logs.csv"
    frac = min(1.0, sample_rows / total_rows)
    rng = np.random.default_rng(RANDOM_STATE)
    chunks = []
    for chunk in pd.read_csv(path, chunksize=200_000):
        if frac < 1.0:
            mask = rng.random(len(chunk)) < frac
            chunk = chunk[mask]
        chunks.append(chunk)
    df = pd.concat(chunks, ignore_index=True)

    y = (df["threat_label"].astype(str) != "benign").astype(int)

    time_feats = _cyclical_time_features(df["timestamp"])
    freq_feats = pd.DataFrame(
        {
            "source_ip_frequency": _frequency_encode(df["source_ip"]),
            "dest_ip_frequency": _frequency_encode(df["dest_ip"]),
            "request_path_frequency": _frequency_encode(df["request_path"]),
            "bytes_transferred": df["bytes_transferred"].astype(float),
        }
    )
    categorical = _one_hot(
        df[["protocol", "action", "log_type", "user_agent"]].astype(str),
        ["protocol", "action", "log_type", "user_agent"],
    )

    X = pd.concat(
        [time_feats.reset_index(drop=True), freq_feats.reset_index(drop=True), categorical.reset_index(drop=True)],
        axis=1,
    )
    return X, y.reset_index(drop=True)


def load_kdd99_corrected() -> tuple[pd.DataFrame, pd.Series]:
    with zipfile.ZipFile(DATA_DIR / "corrected.gz.zip") as zf:
        with zf.open("corrected.gz") as f:
            df = pd.read_csv(io.BytesIO(f.read()), compression="gzip", header=None, names=KDD99_COLUMNS)

    y = (df["label"] != "normal.").astype(int)
    categorical = _one_hot(df[["protocol_type", "service", "flag"]], ["protocol_type", "service", "flag"])
    numeric = df.drop(columns=["protocol_type", "service", "flag", "label"]).apply(lambda c: c.astype(float))

    X = pd.concat([numeric, categorical], axis=1)
    return X, y


def load_synthetic_network_traffic() -> tuple[pd.DataFrame, pd.Series]:
    with zipfile.ZipFile(DATA_DIR / "synthetic_network_traffic.csv.zip") as zf:
        with zf.open("synthetic_network_traffic.csv") as f:
            df = pd.read_csv(f)

    y = df["IsAnomaly"].astype(int)
    X = df.drop(columns=["IsAnomaly"]).apply(lambda c: c.astype(float))
    return X, y


DATASETS = {
    "advanced_cybersecurity": load_advanced_cybersecurity,
    "embedded_system": load_embedded_system,
    "threat_detection_logs": load_threat_detection_logs,
    "kdd99": load_kdd99_corrected,
    "synthetic_traffic": load_synthetic_network_traffic,
}


def run_one(key: str) -> str:
    print(f"\n=== {key} ===")
    X, y = DATASETS[key]()
    X = X.fillna(0.0).astype(np.float32)
    feature_names = list(X.columns)
    print(f"{len(X)} rows, {len(feature_names)} features, anomaly rate {y.mean():.4f}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y
    )

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Real anomaly prevalence isn't known ahead of time in production, but
    # since every dataset here ships a label, calibrating contamination to the
    # observed training-set rate (rather than sklearn's blind "auto") gives a
    # decision threshold that actually lines up with how rare anomalies really
    # are in each dataset.
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
    anomaly_score = -model.decision_function(X_test_scaled)  # higher = more anomalous

    report = classification_report(y_test, y_pred, target_names=["normal", "anomaly"], zero_division=0)
    cm = confusion_matrix(y_test, y_pred)
    try:
        auc = roc_auc_score(y_test, anomaly_score)
    except ValueError:
        auc = float("nan")  # only one class present in y_test

    summary = (
        f"dataset: {key}\n"
        f"rows: {len(X)}  features: {len(feature_names)}  contamination: {contamination:.4f}\n"
        f"ROC-AUC (anomaly score vs. true label): {auc:.4f}\n\n"
        f"confusion matrix [rows=true, cols=pred] (normal, anomaly):\n{cm}\n\n"
        f"{report}"
    )
    print(summary)

    joblib.dump({"model": model, "scaler": scaler, "feature_names": feature_names}, MODELS_DIR / f"{key}.joblib")
    (REPORTS_DIR / f"{key}.txt").write_text(summary, encoding="utf-8")
    return summary


def main() -> int:
    require_datasets()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("datasets", nargs="*", choices=list(DATASETS), default=list(DATASETS),
                         help="Subset of datasets to train (default: all)")
    args = parser.parse_args()
    keys = args.datasets or list(DATASETS)

    for key in keys:
        try:
            run_one(key)
        except Exception as exc:  # keep going even if one dataset fails
            print(f"!! {key} failed: {exc}", file=sys.stderr)

    print(f"\nModels saved to {MODELS_DIR}\nReports saved to {REPORTS_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
