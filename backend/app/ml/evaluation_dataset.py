"""
Leakage-controlled train / evaluation datasets (Sprint 6 KK-06 / PBI-26).

Takes per-upload feature rows from ``features_source_ip_window`` and produces a
train split and an evaluation split that Sprint 7 can train and score against
without rebuilding any of this.

Leakage controls, all enforced in code and re-verified before anything is returned:

1. **Split by upload batch, in time order.** A whole upload batch goes to exactly
   one split; batches are ordered by their earliest window and the *latest* ones
   form the evaluation set (a temporal hold-out), so the model never trains on
   activity that happened after what it is scored on. If batches overlap in time
   that is reported as a limitation rather than hidden.
2. **No repeated activity.** Activity is identified by (source IP, window start).
   Re-uploads of the same file and overlapping batches repeat activity. Before
   splitting, activity is de-duplicated globally: the first occurrence (in batch
   time order) is kept and later ones are dropped, so the same activity can never
   end up on both sides of the split. Rows dropped this way are counted, and the
   subset that would have crossed the split is reported separately.
3. **Both behaviors represented.** Batches carry a ``normal`` / ``suspicious``
   label. The evaluation split is adjusted (without emptying train of a label) so
   both labels appear in it when the data allows; otherwise a warning is recorded.
   IsolationForest is unsupervised, so labels are used only to judge results.
4. **Minimal data.** Rows hold a pseudonymized entity id, window time, upload id,
   label and numeric features. No usernames, hostnames, messages or raw lines ever
   enter the dataset, so there is no free text for secrets or PII to hide in.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field, replace
from datetime import datetime
from pathlib import Path

from app.ml.features_source_ip_window import (
    ENTITY_TYPE,
    FEATURE_NAMES,
    FEATURE_SET,
    WINDOW_SECONDS,
    ExtractionReport,
    WindowFeatures,
)

LABELS = ("normal", "suspicious")
SCHEMA_VERSION = 1

KNOWN_LIMITATIONS = (
    "Labels are per upload batch, not per event: a 'suspicious' batch may contain benign windows.",
    "Only the labeled sample logs/fixtures supplied are covered; real-world volume and variety are not.",
    "One fixed 300 s window per source IP; behavior spanning windows is not represented.",
    "Temporal hold-out is by batch; batches whose time ranges overlap can still share context.",
    "Features come from normalized fields only; sources that parse poorly lower the parser-quality features.",
)


class DatasetError(ValueError):
    """The supplied batches cannot form a valid train/evaluation split."""


@dataclass(frozen=True)
class SourceBatch:
    upload_id: str
    label: str | None
    rows: tuple[WindowFeatures, ...]
    extraction: ExtractionReport | None = None

    @property
    def earliest(self) -> datetime | None:
        return min((row.window_start for row in self.rows), default=None)


@dataclass(frozen=True)
class DatasetRow:
    split: str
    label: str
    upload_id: str
    entity_id: str
    window_start: datetime
    features: dict[str, float]

    @property
    def activity_key(self) -> tuple[str, datetime]:
        return (self.entity_id, self.window_start)


@dataclass
class EvaluationDataset:
    train: list[DatasetRow]
    evaluation: list[DatasetRow]
    manifest: dict = field(default_factory=dict)


def _label(value: str | None) -> str:
    if value is not None and value not in LABELS:
        raise DatasetError(f"label must be one of {LABELS} or None, got {value!r}")
    return value or "unlabeled"


def _rows(batch: SourceBatch, split: str) -> list[DatasetRow]:
    label = _label(batch.label)
    return [
        DatasetRow(split, label, batch.upload_id, row.entity_id, row.window_start, dict(row.features))
        for row in sorted(batch.rows, key=lambda r: (r.window_start, r.entity_id))
    ]


def _choose_eval_batches(ordered: list[SourceBatch], eval_fraction: float) -> tuple[list[SourceBatch], list[SourceBatch]]:
    total = sum(len(b.rows) for b in ordered)
    target = eval_fraction * total
    split_at, held = len(ordered), 0
    while split_at > 1 and held < target:       # always leave at least one batch for train
        split_at -= 1
        held += len(ordered[split_at].rows)
    train, evaluation = ordered[:split_at], ordered[split_at:]

    # Make both labels present in evaluation when train can spare a batch of that label.
    for label in LABELS:
        have = {b.label for b in evaluation}
        if label in have or not any(b.label == label for b in train):
            continue
        spare = [b for b in train if b.label == label]
        if len(spare) >= 2:
            moved = spare[-1]                   # latest batch of that label
            train = [b for b in train if b is not moved]
            evaluation = sorted(evaluation + [moved], key=lambda b: (b.earliest, b.upload_id))
    return train, evaluation


def _deduplicate_activity(ordered: list[SourceBatch]) -> tuple[list[SourceBatch], list[tuple[str, str]]]:
    """Keep the first row per (source IP, window) in batch time order.

    Returns the filtered batches and, per removed row, (batch it was removed
    from, batch that kept the activity)."""

    first_seen: dict[tuple, str] = {}
    removals: list[tuple[str, str]] = []
    result = []
    for batch in ordered:
        kept = []
        for row in sorted(batch.rows, key=lambda r: (r.window_start, r.entity_id)):
            key = (row.entity_id, row.window_start)
            if key in first_seen:
                removals.append((batch.upload_id, first_seen[key]))
            else:
                first_seen[key] = batch.upload_id
                kept.append(row)
        result.append(replace(batch, rows=tuple(kept)))
    return result, removals


def build_dataset(
    batches: list[SourceBatch], *, eval_fraction: float = 0.3, strict: bool = False
) -> EvaluationDataset:
    """Split batches into train/evaluation with the leakage controls above.

    ``strict=True`` raises ``DatasetError`` instead of warning when a split is
    missing normal or suspicious behavior.
    """

    if not 0 < eval_fraction < 1:
        raise DatasetError("eval_fraction must be between 0 and 1")
    ids = [b.upload_id for b in batches]
    if len(set(ids)) != len(ids):
        raise DatasetError("upload ids must be unique; one batch per upload")
    for batch in batches:
        _label(batch.label)
    usable = [b for b in batches if b.rows]
    if len(usable) < 2:
        raise DatasetError("need at least two non-empty upload batches to split by batch")

    ordered = sorted(usable, key=lambda b: (b.earliest, b.upload_id))
    deduped, removals = _deduplicate_activity(ordered)
    nonempty = [b for b in deduped if b.rows]
    if len(nonempty) < 2:
        raise DatasetError("fewer than two upload batches remain after removing repeated activity")
    train_batches, eval_batches = _choose_eval_batches(nonempty, eval_fraction)
    in_eval = {b.upload_id for b in eval_batches}
    across_splits = sum(
        1 for removed_from, kept_in in removals if (removed_from in in_eval) != (kept_in in in_eval)
    )

    train = [row for batch in train_batches for row in _rows(batch, "train")]
    evaluation = [row for batch in eval_batches for row in _rows(batch, "evaluation")]

    warnings: list[str] = []
    for name, rows in (("train", train), ("evaluation", evaluation)):
        present = {r.label for r in rows}
        for label in LABELS:
            if label not in present:
                warnings.append(f"{name} split has no {label} rows")
    if strict and warnings:
        raise DatasetError("; ".join(warnings))

    leakage = verify_no_leakage(train, evaluation)
    if leakage["train_ends_before_evaluation_starts"] is False:
        warnings.append("train and evaluation batches overlap in time; see known limitations")

    dataset = EvaluationDataset(train, evaluation)
    dataset.manifest = _manifest(
        usable, train_batches, eval_batches, train, evaluation, leakage, warnings,
        {"repeated_activity_rows_removed": len(removals),
         "of_which_would_have_crossed_the_split": across_splits},
        eval_fraction, len(batches) - len(nonempty),
    )
    return dataset


def verify_no_leakage(train: list[DatasetRow], evaluation: list[DatasetRow]) -> dict:
    """Re-check the guarantees on the final rows. Raises if a hard guarantee fails."""

    shared_uploads = {r.upload_id for r in train} & {r.upload_id for r in evaluation}
    shared_activity = {r.activity_key for r in train} & {r.activity_key for r in evaluation}
    if shared_uploads:
        raise DatasetError(f"upload batches appear in both splits: {sorted(shared_uploads)}")
    if shared_activity:
        raise DatasetError(f"{len(shared_activity)} activity windows appear in both splits")
    ordered = bool(train and evaluation) and max(r.window_start for r in train) <= min(r.window_start for r in evaluation)
    return {
        "no_shared_upload_batches": True,
        "no_shared_activity_windows": True,
        "train_ends_before_evaluation_starts": ordered,
    }


def _split_summary(rows: list[DatasetRow]) -> dict:
    counts = {label: 0 for label in (*LABELS, "unlabeled")}
    for row in rows:
        counts[row.label] += 1
    return {
        "rows": len(rows),
        "upload_batches": len({r.upload_id for r in rows}),
        "label_counts": counts,
        "first_window": min(r.window_start for r in rows).isoformat(),
        "last_window": max(r.window_start for r in rows).isoformat(),
    }


def _manifest(usable, train_batches, eval_batches, train, evaluation, leakage, warnings, removed,
              eval_fraction, empty_batches) -> dict:
    everything = train + evaluation
    extractions = [b.extraction for b in usable if b.extraction is not None]
    return {
        "schema_version": SCHEMA_VERSION,
        "feature_set": FEATURE_SET,
        "entity_type": ENTITY_TYPE,
        "window_seconds": WINDOW_SECONDS,
        "feature_names": list(FEATURE_NAMES),
        "split_policy": {
            "method": "temporal hold-out by upload batch",
            "eval_fraction_target": eval_fraction,
            "train_batches": [b.upload_id for b in train_batches],
            "evaluation_batches": [b.upload_id for b in eval_batches],
            "batches_skipped_empty_or_fully_duplicate": empty_batches,
        },
        "train": _split_summary(train),
        "evaluation": _split_summary(evaluation),
        "removed_for_leakage_control": removed,
        "leakage_checks": leakage,
        "source_records": {
            "total": sum(e.total_records for e in extractions),
            "used": sum(e.used_records for e in extractions),
            "duplicates": sum(e.duplicate_records for e in extractions),
            "dropped_missing_timestamp": sum(e.dropped_missing_timestamp for e in extractions),
            "dropped_invalid_ip": sum(e.dropped_invalid_ip for e in extractions),
        } if extractions else None,
        # Share of rows where each feature is non-zero: a quick read on which
        # signals the dataset actually exercises (all-zero columns teach nothing).
        "feature_nonzero_fraction": {
            name: round(sum(1 for r in everything if r.features[name] != 0) / len(everything), 4)
            for name in FEATURE_NAMES
        },
        "warnings": warnings,
        "known_limitations": list(KNOWN_LIMITATIONS),
        "fields_excluded": ["username", "hostname", "raw_message", "parsed_data", "command", "file_path"],
    }


def pseudonymize(value: str, salt: str) -> str:
    """Keyed hash of an entity id. A salt is mandatory: unsalted hashes of IPv4
    addresses can be reversed by brute force."""

    if not salt:
        raise DatasetError("a non-empty salt is required to pseudonymize entity ids")
    return hmac.new(salt.encode(), value.encode(), hashlib.sha256).hexdigest()[:16]


def _row_json(row: DatasetRow, salt: str) -> str:
    return json.dumps(
        {
            "split": row.split,
            "label": row.label,
            "upload_id": row.upload_id,
            "entity": pseudonymize(row.entity_id, salt),
            "window_start": row.window_start.isoformat(),
            "features": [row.features[name] for name in FEATURE_NAMES],
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def export_dataset(dataset: EvaluationDataset, directory: Path, *, salt: str) -> list[Path]:
    """Write ``train.jsonl``, ``evaluation.jsonl`` and ``manifest.json``.

    Feature values are written in ``manifest['feature_names']`` order.
    Output is byte-for-byte reproducible for the same input and salt.
    """

    directory.mkdir(parents=True, exist_ok=True)
    written = []
    for name, rows in (("train", dataset.train), ("evaluation", dataset.evaluation)):
        path = directory / f"{name}.jsonl"
        path.write_text("".join(_row_json(row, salt) + "\n" for row in rows), encoding="utf-8")
        written.append(path)
    manifest = directory / "manifest.json"
    manifest.write_text(json.dumps(dataset.manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    written.append(manifest)
    return written
