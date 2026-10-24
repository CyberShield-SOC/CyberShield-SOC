# Anomaly-detection eval infrastructure

Shared, fully synthetic harness for validating the three IsolationForest rules
(`behavioral_anomaly_login`, `behavioral_anomaly_egress`,
`behavioral_anomaly_threat_log`). No dataset files, no network access, no
dependency on anything outside this repo.

**Status:** all three feature sets have synthetic evals. Login and egress
were rebuilt from scratch (S7-01/PBI-26) against the real feature extractors
and rule gating — the generators that existed before this were only ever
reference material in a stash, never committed, with no reproducible numbers
behind them (see `ml_experiments/README.md` §9-10 for the findings).

## Layout

| File | Role |
|---|---|
| `harness.py` | `SPECS` (one entry per feature set), `isolated_scenario()` — the per-scenario FEATURE_SET swap + savepoint rollback, `Scenario` (ingest / train / read back scores) |
| `metrics.py` | Wilson CI, threshold sweep, ROC-AUC, separation margin, recorded library versions |
| `synthetic_threat_log.py` | Seeded population + injection generators for `threat_log` (ported from `ml_experiments/threat_log_false_positive_power_check.py`) |
| `synthetic_login.py` | Seeded population + injection generators for `login_behavior` |
| `synthetic_egress.py` | Seeded population + injection generators for `egress_volume` |
| `scenarios.py` | `run_threat_log_scenario()`, `run_login_scenario()`, `run_egress_scenario()` — one seeded scenario per feature set, using the harness |
| `test_threat_log_overlap.py` | Bands for `threat_log`'s v2 (overlapping) population (always run) |
| `test_login_egress_overlap.py` | Bands for `login_behavior` and `egress_volume`'s v2 populations (always run) |
| `test_harness_isolation.py` | Proves two scenarios in one session share no state (always run, no API/model cost) |

## The two guard cases are regression guards, not demonstrated blind spots

`threat_log`'s `exfil_popular`, `login_behavior`'s `new_geo_common_country`,
and `egress_volume`'s `popular_dest_exfil` all inject an attack whose only
"tell" is a value (destination or country) that happens to be common across
other entities in the scenario. None of the three feature sets has an
org-wide rarity feature, so none of them can use that popularity signal —
but the measured result is that **all three are still substantially
detected today**, via the signal each model already has (bytes/volume for
the two destination-based cases, `is_new_geo` for the country-based case),
independent of how popular the value actually is. These cases exist to catch
a *future* regression: if an org-wide rarity feature is ever added and used
to down-weight "common" destinations/countries, it must not suppress these
genuinely-anomalous events just because they happen to target something
popular. Re-run the relevant powered script after such a change and confirm
the guard case's score stays comparably negative.

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
.venv/Scripts/python.exe -m pytest tests/anomaly_eval -q          # isolation + overlap-band tests for all three feature sets; always safe, no API/model cost
```

The powered studies (open a session against the real dev database, never commit —
see each script's own docstring):

```
backend/.venv/Scripts/python.exe ml_experiments/threat_log_false_positive_power_check.py
backend/.venv/Scripts/python.exe ml_experiments/login_egress_overlap_power_check.py
```

## Findings

See `ml_experiments/README.md` §6-8 (threat_log) and §9-10 (login_behavior,
egress_volume) for the full writeup: detection/FP rates with Wilson CIs,
single-feature AUC diagnostics, threshold sweeps, and honest held-out
threshold tuning for login/egress. Headline: threat_log's shipped `-0.12`
already reaches a low FP rate (~0.8%), at the cost of weak (~30%) detection.
Login and egress ship an unvalidated `-0.02` that produces a *high* FP rate
(27-50% in this synthetic population) with no low-FP operating point found
for login at all; egress has a weak-but-real one (~7-13% detection @ ~0.4%
FP). All three thresholds have no live effect yet (`shadow_mode=True` on
every rule) — this is advisory/shadow-mode review data, not a live alerting
gap.

§9-10's numbers reflect two generator bugs found by an independent code
review and fixed after the first pass (see `ml_experiments/README.md` §9-10
for what each was and how it was corrected): login attacker accounts had no
synthetic baseline history, so `is_new_geo` was stuck at `True` for every
attack regardless of intent; egress's `spread_loud`/`spread_subtle` sampled
destinations with replacement from a pool too small to reach the distinct
count they documented. Both are fixed; the numbers above are post-fix.
