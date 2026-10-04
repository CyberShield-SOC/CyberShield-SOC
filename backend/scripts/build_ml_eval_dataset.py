"""Build the leakage-controlled ML train/evaluation dataset from labeled log files.

    cd backend
    ML_DATASET_SALT=<secret> python scripts/build_ml_eval_dataset.py \\
        --normal ../sample-logs/kk_normal.csv ../sample-logs/auth.log \\
        --suspicious ../sample-logs/kk_suspicious.csv \\
        --out ../ml_experiments/datasets/sprint6

Each file is one upload batch carrying the label of the flag it was passed under.
Files go through the same parser and normalizer as a real upload. Output
(train.jsonl, evaluation.jsonl, manifest.json) contains pseudonymized entity ids and
numeric features only. The salt comes from --salt or ML_DATASET_SALT and is never
stored; keep it out of git. The default output folder is git-ignored.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.detection.normalize import log_record_from_entry  # noqa: E402
from app.ml.evaluation_dataset import DatasetError, SourceBatch, build_dataset, export_dataset  # noqa: E402
from app.ml.features_source_ip_window import extract_window_features  # noqa: E402
from app.parsers.log_parser import parse_log  # noqa: E402


def load_batch(path: Path, label: str) -> SourceBatch:
    parsed = parse_log(path.read_text(encoding="utf-8"), path.name)
    records = [
        log_record_from_entry(entry, str(parsed["format"])).model_copy(update={"upload_id": path.name})
        for entry in parsed["entries"]
    ]
    rows, report = extract_window_features(records)
    return SourceBatch(upload_id=path.name, label=label, rows=tuple(rows), extraction=report)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--normal", nargs="+", type=Path, default=[], help="files of normal behavior")
    parser.add_argument("--suspicious", nargs="+", type=Path, default=[], help="files of suspicious behavior")
    parser.add_argument("--out", type=Path, default=Path("../ml_experiments/datasets/sprint6"))
    parser.add_argument("--salt", default=os.environ.get("ML_DATASET_SALT", ""))
    parser.add_argument("--eval-fraction", type=float, default=0.3)
    parser.add_argument("--strict", action="store_true", help="fail instead of warn if a split lacks a label")
    args = parser.parse_args()

    names = [p.name for p in (*args.normal, *args.suspicious)]
    if len(set(names)) != len(names):
        print("error: file names must be unique (they are used as upload ids)", file=sys.stderr)
        return 2
    if not args.salt:
        print("error: set --salt or ML_DATASET_SALT (needed to pseudonymize IP addresses)", file=sys.stderr)
        return 2
    try:
        batches = [load_batch(p, "normal") for p in args.normal] + [load_batch(p, "suspicious") for p in args.suspicious]
        dataset = build_dataset(batches, eval_fraction=args.eval_fraction, strict=args.strict)
    except DatasetError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    for path in export_dataset(dataset, args.out, salt=args.salt):
        print(f"wrote {path}")
    m = dataset.manifest
    print(f"train={m['train']['rows']} evaluation={m['evaluation']['rows']} warnings={m['warnings']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
