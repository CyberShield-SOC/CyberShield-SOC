# Anomaly-detection eval infrastructure

Shared, fully synthetic harness for validating the three IsolationForest rules
(`behavioral_anomaly_login`, `behavioral_anomaly_egress`,
`behavioral_anomaly_threat_log`). No dataset files, no network access, no
dependency on anything outside this repo.

**Status:** infrastructure only. This package currently proves the harness is
correct (isolation tests, always run) and hosts the threat-log generators the
powered study now imports (parity-verified against the prior in-script
version). Login and egress synthetic evals have not been written yet — the
harness (`SPECS` in `harness.py`) already covers all three feature sets, so
writing them is adding generators plus assertions, not new infrastructure.

## Layout

| File | Role |
|---|---|
| `harness.py` | `SPECS` (one entry per feature set), `isolated_scenario()` — the per-scenario FEATURE_SET swap + savepoint rollback, `Scenario` (ingest / train / read back scores) |
| `metrics.py` | Wilson CI, threshold sweep, ROC-AUC, separation margin, recorded library versions |
| `synthetic_threat_log.py` | Seeded population + injection generators for `threat_log` (ported from `ml_experiments/threat_log_false_positive_power_check.py`) |
| `scenarios.py` | `run_threat_log_scenario()` — one seeded scenario, using the harness |
| `test_harness_isolation.py` | Proves two scenarios in one session share no state (always run, no API/model cost) |

## Isolation, and why it needs proving

The rules and their `train_*.py` modules read a **module-level `FEATURE_SET`
name**, and training pulls "every snapshot stored under that name". A model
also writes to `entity_baselines`, which is **not** keyed by feature set at
all. `isolated_scenario()` makes each scenario safe against both:

1. swaps in a globally-unique name, in both the rule module and its paired
   train module, restored in a `finally` (even on exception);
2. wraps the scenario in a database savepoint, rolled back when it ends, so
   snapshots, models, and any `entity_baselines` row are gone afterward.

`test_harness_isolation.py` is not a smoke test — it was mutation-tested: each
of the three isolation mechanisms (restoring the globals, rolling back the
savepoint, generating a unique name) was individually broken and confirmed to
make a specific test fail, then restored. A negative-control test
(`test_negative_control_without_isolation_state_does_leak`) runs the same
scenario shape with the isolation deliberately removed and shows the
contamination is real (115 snapshots instead of 60, i.e. scenario B trained on
A's data too) — proof the positive tests are not vacuous.

## Reproducibility: bands, not exact scores

No library version is pinned beyond `requirements.txt`'s existing ranges (sklearn,
numpy). A future library upgrade can shift exact float scores slightly, so any
eval built on this harness must assert **statistical bands** (a detection rate
with a Wilson CI, a false-positive rate below a bound, ROC-AUC above a
threshold) rather than an exact score. Any report produced from this package
should call `metrics.environment_versions()` and record them, so a future
discrepancy can be attributed to a version change rather than treated as a
silent regression.

## Threat-log: ported, not rewritten, and parity-checked

`synthetic_threat_log.py` and `run_threat_log_scenario()` are the same
population/injection logic as the prior `run_once()` inside
`ml_experiments/threat_log_false_positive_power_check.py`, with one structural
change (a per-scenario line-number counter instead of a module-global one —
line numbers are never a model feature, so this cannot affect scores). Before
the powered script was switched to import from here, the two implementations
were run side by side on 8 (novelty_level, seed) scenarios (2 novelty levels ×
2 seeds × both fresh per-implementation sessions) and their 856 individual
scores compared: **bit-identical, max |old − new| = 0.0**. The powered script
now imports `run_threat_log_scenario` directly; its report-building and
printed-statistics code is untouched.

## Running what exists today

```
cd backend
.venv/Scripts/python.exe -m pytest tests/anomaly_eval -q          # isolation tests only; always safe, no API/model cost
```

The powered threat-log study (writes `ml_experiments/reports/threat_log_false_positive_powered.txt`,
opens a session against the real dev database, never commits):

```
backend/.venv/Scripts/python.exe ml_experiments/threat_log_false_positive_power_check.py
```

## What's next (not built yet; needs a separate go-ahead)

Login and egress synthetic evals, same shape as threat-log's: a fast,
always-run version asserting coarse bands (separation, no gross false-positive
rate) at the shipped threshold, plus a local-only powered tier
(`RUN_ANOMALY_EVAL=1`) producing a report with confidence intervals and a
threshold sweep — the two unvalidated thresholds this whole effort exists to
check. See `docs/assistant-eval.md`'s sibling doc (once written) for the case
list.
