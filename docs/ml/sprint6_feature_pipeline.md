# Sprint 6 ML work: correlation fixtures, feature pipeline, evaluation dataset

Owner: Kapil Khanal (KK-01, KK-02, KK-05, KK-06). Everything here is pure Python on
normalized events; none of it touches the database schema or any existing module.

## KK-01 / KK-02: correlation fixtures and evaluation

| Piece | Location |
| --- | --- |
| 20 fixtures (positive, negative, duplicate, boundary) | `backend/tests/correlation_fixtures/cases.py` |
| Evaluator (missed groupings, false groupings, nonmatch violations, duplicate links) | `backend/tests/correlation_fixtures/evaluate.py` |
| Pytest run (per fixture, order-independence, evaluator self-checks) | `backend/tests/test_correlation_fixtures.py` |
| Plain-text report, exit 1 on failure | `python backend/scripts/evaluate_correlation_fixtures.py [--out report.txt]` |

Each fixture states its input records, expected groups, expected evidence links (the
`event_ids` and `alert_ids` of each expected group), expected nonmatches (event-id pairs
that must never share a group) and the window behavior it exercises.

Engine rules the fixtures encode (from `app/services/correlation.py`):
windows are anchored at the first event and inclusive at both ends, never chain; groups
are partitioned per rule policy, entity and upload scope (different rules never merge);
repeated references to an event collapse to one evidence link; unknown entities and
unparseable timestamps are skipped.

Current result against the engine on `main`: 20/20 pass, no missed or false groupings.

**For review (Paul / Marvellous):** `account_names_are_case_sensitive` records that
`Alice` and `alice` are different accounts today. If the team wants case-insensitive
usernames, that is a behavior change and this fixture is the one to update.
To report a defect, send the fixture name; every input is reproducible from it.

## KK-05: per-source-IP feature vectors

`backend/app/ml/features_source_ip_window.py`, feature set `source_ip_window`, entity
type `source_ip` (valid for `ml_feature_snapshots`). `extract_window_features(records)`
returns rows sorted by (window start, IP) plus an `ExtractionReport`;
`WindowFeatures.snapshot_kwargs()` plugs into the existing `save_feature_snapshot`.

- **Unit:** source IP x 300 s tumbling UTC window, `[start, start+300)`, epoch-anchored.
  Deliberately different from correlation windows (see the module docstring).
- **Features (13, fixed order):** event_count, failed_login_count, success_login_count,
  failed_to_success_ratio (`failed / (success + 1)`), unique_users, unique_hosts,
  sudo_failure_count, mean_gap_seconds, min_gap_seconds, hour_sin, hour_cos,
  known_status_ratio, known_event_type_ratio.
- **Not included:** unique source IPs. The key is the source IP, so it would always be 1.
- **Missing values:** unusable records (no timestamp / no valid IP) are dropped and counted,
  never guessed; counts default to 0; single-event windows get 300 s for both gap features.
- **Determinism:** floats rounded to 6 places, sorted output, duplicate records (same log id,
  or same upload + line) counted once. Same stored events give identical vectors on every run.
- **Database rows:** `records_from_logs(logs)` converts stored `Log` rows with the same
  normalizer the correlation service uses.

## KK-06: leakage-controlled evaluation dataset

`backend/app/ml/evaluation_dataset.py`, CLI `backend/scripts/build_ml_eval_dataset.py`.

1. Whole upload batches go to one split; the latest batches form evaluation.
2. Repeated activity (same IP and window) is removed globally, keeping the earliest.
3. Both `normal` and `suspicious` are represented in each split when the data allows
   (otherwise a warning, or an error with `--strict`).
4. Output holds a salted pseudonym of the IP, window time, upload id, label and numbers.
   No usernames, hosts, messages or raw lines. A salt is required and is never stored.

The manifest records row/batch counts per split and label, source-record and drop counts,
non-zero share per feature, the leakage checks, warnings and known limitations.
Output is byte-for-byte reproducible for the same input and salt.

**Known limitations**
- Labels are per batch, not per event.
- Label balancing can move a batch across the time order; when it does, the manifest
  reports `train_ends_before_evaluation_starts: false` with a warning.
- The repo's sample logs only yield about 14 windows. The existing trainers require 50
  snapshots (`MIN_SAMPLES`), so Sprint 7 needs more labeled data than the samples provide.

## Verification

Backend CI already runs `pytest tests` over everything above (all of it is `no_db`, so it
needs no extra service). Locally: `cd backend && python -m pytest tests/test_correlation_fixtures.py
tests/test_ml_source_ip_window_features.py tests/test_ml_evaluation_dataset.py`.
