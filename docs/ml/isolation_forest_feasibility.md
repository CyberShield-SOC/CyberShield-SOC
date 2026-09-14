# Feasibility: `sklearn.ensemble.IsolationForest` for anomaly detection

Scoped answer to one question: could CyberShield use `IsolationForest` to catch things the
28 rule-based detectors (`backend/app/detection/rules/`) miss, and if so, what data would it
need? It complements, and does not replace,
[`docs/backend_data_requirements_for_ml.md`](../backend_data_requirements_for_ml.md), which
predates the Group A/B/C rule work and the `entity_baselines`/`host_heartbeats`/
`threat_indicators` tables described below.

## Implementation status

Two pilots are built and live-tested end to end, sharing one plumbing layer:

- `backend/app/ml/pipeline.py` — the shared implementation every pilot now uses for the three
  steps that used to be duplicated per pilot: `load_active()` (load the active model once per
  `analyze()` batch, or `None` if none exists / its schema no longer matches), `record_and_score()`
  (persist a feature snapshot, scoring it against the model when one is loaded), and
  `fit_and_save_model()` (fit an `IsolationForest`, compute per-feature mean/std with an
  epsilon floor, serialize, and save a new model version). Adding a third pilot means writing
  a `features_*.py` and a rule; the fit/score/persist mechanics are no longer duplicated.
- **Pilot #1 — login behavior** (§2): `backend/app/ml/features.py`
  (`hour_sin/cos`, `dow_sin/cos`, `is_new_geo`), `backend/app/ml/train_login_behavior.py`,
  `backend/app/detection/rules/behavioral_anomaly_login.py` (frontend: `R-D01`).
- **Pilot #2 — egress volume** (§2's second-ranked candidate): `backend/app/ml/features_egress_volume.py`
  (`log_bytes_out`, `connection_count`, `distinct_destinations`, `hour_sin/cos`, entity type
  `host` instead of `account`), `backend/app/ml/train_egress_volume.py`,
  `backend/app/detection/rules/behavioral_anomaly_egress.py` (frontend: `R-D02`). Scores one
  host's hourly egress bucket jointly on volume, connection count, destination spread, and
  time of day — catching combinations that stay under `egress_volume_anomaly`'s single-dimension
  threshold on their own.
- `ml_feature_snapshots` / `ml_models` tables (migrations `e3f8b1a4c962`, `f2a9c7e410b3`) — the
  persisted feature history §3.2 says doesn't exist for the running-scalar baselines; it now
  does, shared by both pilots and keyed by `feature_set`. The second migration added a nullable
  `score` column so a snapshot can carry the score it was given, whether or not that score ever
  became an alert.
- **Genuine two-stage shadow mode** (§5.5), no longer just "no model = shadow mode": (1) no
  active model for a `(feature_set, entity_type)` — pure data collection, nothing is scored;
  (2) once a model exists, `params.shadow_mode` (rule default `True`) still gates whether a
  computed score becomes an `Alert` — every event is scored and its score persisted on
  `MLFeatureSnapshot.score` either way, so a shadow-mode deployment is reviewable rather than a
  black box. `GET /ml/scores?feature_set=...&below=...` surfaces the lowest (most anomalous)
  recorded scores for that review, independent of whether shadow mode is on.
- **Model lifecycle API** (§5.2's "no retraining trigger, model rollback, or admin UI" gap,
  now partially closed at the API layer): `backend/app/routers/ml_models.py` —
  `GET /ml/models` (every version, `is_active` flag, sample count, params), `POST
  /ml/models/{feature_set}/train` (Admin-only, synchronous, dispatches through
  `backend/app/ml/registry.py` so each pilot's trainer is one registry entry), and `POST
  /ml/models/{model_id}/activate` (Admin-only rollback/roll-forward — deactivates every sibling
  version of that `(feature_set, entity_type)` and takes effect on the very next upload, no
  redeploy). **Still missing**: no *frontend* panel exposes any of this yet — it's
  `curl`/API-only today, unlike every other admin-facing feature in this project (threat
  intel, host heartbeats), which pairs a backend feature with a dashboard panel.
- Explainability (§4.5, §5.7): every alert's `evidence` carries the raw score, the threshold,
  and per-feature z-score deviations from the training population's own mean — not a bare
  number.
- Tests: `backend/tests/test_ml_behavioral_anomaly.py` (19 cases, including the two shadow-mode
  gate tests added in this phase), `backend/tests/test_ml_egress_volume.py` (6 cases),
  `backend/tests/test_ml_models_api.py` (8 cases covering train/list/activate/scores + RBAC).
  Fixed `random_state` throughout, per §5.4. One of the login-pilot tests is a real regression
  caught by live-testing against the running app: a single-day training set gives
  `dow_sin`/`dow_cos` ~zero variance, and a floating-point std of order 1e-16 slipped past an
  exact-zero divide-by-zero guard, producing z-scores in the hundreds of trillions instead of a
  sane single digit. Fixed with an epsilon floor (`stds[stds < 1e-6] = 1.0`) inside
  `fit_and_save_model()`, so both pilots get the fix for free.

Still real gaps, not yet addressed:

- **Only one feature set per pilot is pooled globally**, not per-entity — the §3.3 tradeoff,
  deliberately: per-entity models would need far more history per entity than a typical
  deployment has yet.
- **No automatic retraining trigger** — `POST /ml/models/{feature_set}/train` exists, but
  nothing calls it on a schedule or in response to snapshot volume; an admin (or an external
  cron hitting the endpoint) has to decide when to retrain.
- **No frontend admin UI** for any of the model-lifecycle or shadow-mode-review endpoints —
  they exist and are tested at the API layer only.
- **Only two of the four pilot candidates exist.** `outbound_beaconing` and `host_sweep`/`port_scan`
  (§2's other two candidates) are still un-started — the §2 table's reasoning for why they're
  good candidates still stands, but no code exists for them, and nothing about the shared
  `pipeline.py` layer changes that estimate.
- **Real volume**: both pilots were demonstrated with synthetic datasets generated for the
  purpose (hundreds of samples with deliberate jitter so `IsolationForest` has something to
  split on), not organic upload history — §3.3's point about lab-deployment data volume being
  too thin for real training remains true for actual production use.
- **No background job runner**: `POST /ml/models/{feature_set}/train` is synchronous — it blocks
  the request for however long the fit takes. Fine at current sample sizes; not something to
  build a bigger feature_set on without adding real background-job infrastructure first (§5.3).

## Verdict

**Feasible as a complementary, advisory scoring layer, and two pilots now prove it end to end
on a shared implementation.** The things §1-§5 originally said were missing — a persisted
feature history, a training job outside the request path, an explainability layer, a real
shadow-mode review step, and model version lifecycle management — all exist now, for two
feature sets, without duplicating the fit/score/persist logic per pilot. What's unchanged: real
per-entity data volume still doesn't exist outside a synthetic demo, there's no frontend for any
of this, no automatic retraining trigger, and nothing here should be treated as validated
against real attack data.

## 1. What `IsolationForest` actually does

`sklearn.ensemble.IsolationForest` is unsupervised: it needs no labeled "this was an attack"
examples, which fits this project — CyberShield has no labeled attack dataset, only rule
outputs and analyst-assigned incident status. It works by randomly partitioning numeric
feature space with an ensemble of trees; points that isolate in few splits (short average
path length) score as anomalous. Practically:

- **Input**: a 2D numeric matrix, `(n_samples, n_features)`. Categorical fields (username,
  process name, country) must be turned into numbers first (counts, one-hot, or target
  encoding) — the algorithm itself has no notion of a country code or an IP address.
- **Output**: `.predict()` gives `-1`/`1`; `.score_samples()` / `.decision_function()` give a
  continuous score, which is the more useful one here — it can feed `Alert.confidence`
  (`backend/app/detection/models.py:79-89`) the same way rule-computed confidence does today.
- **Key parameters**: `n_estimators` (tree count, default 100), `max_samples` (default
  `min(256, n_samples)` — the classic guidance is you want meaningfully more than 256 samples
  per model, not fewer), and `contamination` (expected anomaly fraction — `'auto'` works but a
  bad guess here directly inflates or starves the alert rate).
- **What it's bad at**: sequence-order behavior (a scan pattern, a specific command sequence),
  and anything a hand-written threshold already nails precisely — `brute_force_login`'s "5
  fails in 60s" doesn't need a forest, it needs a counter. IsolationForest earns its keep on
  *multi-dimensional* "this combination is weird for this entity" judgments that no single
  threshold rule expresses.

## 2. Where it would fit in this codebase

The rule engine (`DetectionEngine.run`, `backend/app/detection/engine.py:133-147`) is
deterministic and explainable by design — every alert already carries a plain-English
`description` and, since the schema-v2/v3 work, a MITRE technique, a confidence score, and an
`evidence` dict (`backend/app/detection/models.py:70-96`). An IsolationForest score is neither
deterministic (depends on training data) nor self-explaining (a raw anomaly score means
nothing to an analyst on its own). So the natural fit is a **new, separate rule category** —
call it Group D — that runs *after* the existing rules, reads whatever feature vector the
upload just produced, scores it against a **pre-trained, per-`entity_type` model**, and emits
a low-confidence advisory alert (e.g. `behavioral_anomaly`) only when the score crosses a
threshold, always with the specific feature values that drove it attached as `evidence` —
never a bare number.

Best pilot candidates, because they already touch `entity_baselines`
(`backend/app/models/entity_baseline.py`) and already reason about numeric drift from a
per-entity norm:

| Rule | Existing signal | What IsolationForest adds |
| --- | --- | --- |
| `egress_volume_anomaly` | EWMA mean/variance of one feature (`bytes_out` per window) | Joint scoring across bytes, distinct destinations, connection count, hour-of-day at once, instead of one dimension at a time |
| `off_hours_login` / `dormant_account_activity` | Fixed hour window; single last-login timestamp | A per-account "normal" learned from hour, day-of-week, and days-since-last-login jointly |
| `outbound_beaconing` | Hand-tuned jitter/interval thresholds (`backend/app/detection/rules/outbound_beaconing.py`) | Same features (interval, jitter, connection count, bytes) without hand-picking the jitter cutoff |
| `host_sweep` / `port_scan` | Fixed count thresholds | Distinct-hosts/ports-touched rate scored against that source's own history, not a global constant |

Everything else — the Group A host-integrity rules, `threat_intel_match`, `ssh_key_added` —
is pattern-matching against a specific known-bad signature. There's no "normal" distribution
to learn there; IsolationForest has nothing to add.

## 3. Data needed

### 3.1 What's already available per event

`LogRecord` (`backend/app/detection/models.py:14-67`) is the row-level contract every rule
sees. Fields with real feasibility as ML inputs, already numeric or trivially encodable:

- **Temporal**: `timestamp` → hour-of-day, day-of-week (cyclical-encode both, e.g. sin/cos).
- **Network volume**: `bytes_out`, `bytes_in`, `port`, `protocol` — populated only for
  CSV/JSON flow/proxy uploads with the right columns (see
  `backend/app/detection/normalize.py:14-40` for the accepted column aliases); syslog/apache
  sources leave these `None`.
- **DNS**: `dns_query` (→ length, Shannon entropy — already computed once per query in
  `dns_tunneling.py`'s `shannon_entropy()`), `dns_query_type`.
- **Geo**: `country`, `asn`, `latitude`, `longitude` — from the log itself or the optional
  local GeoIP database (`backend/app/detection/geoip.py`); absent otherwise.
- **Identity/behavioral**: `username`, `ip_address`, `hostname`, `event_type`, `status` — all
  categorical, need encoding (frequency/count encoding is simplest and matches "how often
  does this entity normally do X").

Everything else on `LogRecord` (`process`, `command`, `file_path`, `audit_*`) is
pattern-matching material for Group A, not IsolationForest feature material — there's no
meaningful "distance" between two shell commands without heavy NLP-style featurization, which
is a separate project.

### 3.2 The actual gap: no feature history is persisted

This is the real blocker, not the algorithm. `entity_baselines`
(`backend/app/models/entity_baseline.py`) is intentionally a **scalar running-stats store** —
one JSON blob per `(entity_type, entity_id, baseline_key)`, overwritten in place every upload
(see `egress_volume_anomaly.py`'s EWMA update, or `dormant_account_activity.py`'s single
`last_login_at`). That's correct for the rules that use it today, which only ever need "the
current mean" or "the last timestamp" — but it means **no history survives**. A forest needs
the last N feature vectors, not the current running average of one of them.

Concretely, building a training set today would require either:

1. **A new table**, e.g. `ml_feature_snapshots(entity_type, entity_id, window_start,
   features JSONB)`, populated once per upload alongside the existing baseline updates in
   `upload.py`'s pipeline — additive, no change to existing rules; or
2. **Reconstructing features from `Log.parsed_data`** after the fact
   (`backend/app/models/log.py:112-117` — every parsed event is kept forever, JSONB, per
   upload). This works retroactively on data already ingested, but means writing a batch
   feature-extraction job that re-derives per-window aggregates from raw rows rather than
   reading them off a table — slower, and duplicates logic that already lives in the rules.

Either way, this doesn't exist today. It's a schema/pipeline addition, not a config change.

### 3.3 How much data, realistically

`max_samples` defaults to 256; the standard guidance is to have comfortably more samples than
that per model, and `contamination` needs a believable estimate of what fraction of windows
are actually anomalous for that entity. Two consequences for this project specifically:

- **This repo's own `sample-logs/detection/` fixtures are far too small.** They're built to
  trigger one rule with a handful of events each (see
  `sample-logs/detection/generate_samples.py`) — nowhere near the hundreds of per-entity
  samples a forest needs. They're proof the pipeline runs, not training data.
- **Per-entity cold start is the norm, not the exception**, the same problem
  `dormant_account_activity` and `egress_volume_anomaly` already gate on
  (`min_samples`/`min_history` params). A brand-new host or account has no history to be
  anomalous *relative to* — any ML rule needs the same "not enough history yet, skip" guard
  those rules already use, probably reusing the same pattern.
- Realistic accumulation needs **weeks of continuous uploads per entity**, not one-off log
  drops. A lab/demo deployment (this project's current state) won't have enough data for a
  meaningful *per-entity* model for a long time; a shared *per-entity-type* model (all hosts
  pooled, say) needs less but loses the "weird for **this** host" precision that's the whole
  point.

## 4. What it would take to actually build this

1. Add `scikit-learn` to `backend/requirements.txt` (pulls in `numpy`/`scipy` as
   dependencies — a meaningfully heavier install than anything currently there; worth
   checking Railway/nixpacks build time and image size before committing to it).
2. Add the feature-snapshot table (§3.2) and start populating it — this alone is useful
   independent of ML, since it'd also make future rule tuning and analyst review easier.
3. Write an **offline** training job (not in the FastAPI request path): pull snapshots for an
   `entity_type`, assemble the matrix, fit `IsolationForest`, persist the fitted model
   (`joblib`) somewhere versioned — a `ml_models` table (bytes + metadata) is simplest, no new
   infra needed.
4. Add a scoring step to the upload pipeline that loads the current model for an
   `entity_type`, scores that upload's new feature vectors, and emits `behavioral_anomaly`
   alerts above a chosen score cutoff — mirroring how `host_log_silence` already handles
   "state that isn't ready yet" (§3.3) and "check on demand" (there's no scheduler in this
   codebase — see `backend/app/routers/detection.py`'s `/detection/host-silence/check` for
   the existing pattern of an on-demand endpoint standing in for a cron job; retraining would
   need the same kind of manual/external trigger).
5. Add an explainability step: since a raw anomaly score isn't an acceptable `description` on
   its own, compute and store per-feature deviation from that entity's own historical mean
   (cheap: `(value - mean) / stdev` per feature, already the shape of math
   `egress_volume_anomaly.py` does) so the alert can say *which* feature was unusual, not just
   "this was unusual."

## 5. Additional requirements: feature engineering, lifecycle, and governance

§4 covers the pipeline shape. These are the things that only show up once you try to actually
run it — mostly lifecycle and governance, not algorithm.

### 5.1 Feature engineering plumbing

- An encoding scheme for categorical fields (`username`, `country`, `asn`, `event_type`) —
  count/frequency encoding is simplest and matches "how often does this entity normally do X."
- A **per-source-format feature set**, not one universal one. A syslog upload never populates
  `bytes_out`/`bytes_in`; a CSV flow export never populates `dns_query`. Training one model on
  a feature matrix full of nulls is a mess — realistically this means separate feature sets
  per rule/use-case (a "login behavior" model vs. an "egress volume" model), which multiplies
  the number of models to maintain, not one model that does everything.
- Missing-value handling for features that are expected for a given feature set but
  occasionally absent (a login event with no resolvable geo, say).

### 5.2 Model lifecycle — the part with no existing equivalent in this codebase

- **Storage + versioning**: a fitted model needs a home — a `ml_models` table storing the
  `joblib` bytes plus training date, sample count, and feature-schema version, so scoring code
  can confirm a loaded model actually matches the shape of the features it's about to score.
- **A retraining trigger**: same gap as `host_log_silence` — no scheduler exists in this
  codebase, so retraining needs the same on-demand-endpoint-standing-in-for-a-cron pattern
  already used for `/detection/host-silence/check`.
- **Rollback**: if a retrained model starts flooding alerts, there needs to be a way back to
  the last-known-good model without a code deploy.
- **Contamination estimation**: `IsolationForest`'s `contamination` parameter needs a
  believable guess at what fraction of windows are actually anomalous. There's no ground
  truth for this; the closest proxy is the existing rule engine's own historical alert rate
  per entity, used as a rough calibration target rather than a precise input.

### 5.3 Where training actually runs

Detection today runs synchronously inside `/upload`'s request handler. Fitting a forest is
too slow for that path, and there's no worker/background-job infrastructure in this app (a
single FastAPI service on Railway). Training needs to run somewhere else — a separate script
invoked manually, or a genuine background worker — which is new infrastructure, not a code
change.

### 5.4 Testing that isn't inherently flaky

`IsolationForest` is stochastic. Tests need a fixed `random_state` for reproducibility, plus
synthetic fixtures with a *known*, deliberately planted outlier among otherwise-normal points
— unlike the rule engine's `assert alerts == []`-style tests, there's no way to assert "it
learned correctly," only "it flagged the planted outlier and not the normal points."

### 5.5 Rollout governance

Given how much analyst trust costs to rebuild once lost to noisy alerts, this wants a
**shadow-mode phase** first: compute and log scores without creating alerts, let an analyst
review a sample of what would have fired, and only turn on real alerts once the false-positive
rate looks tolerable. That's process, not code, but it's a real prerequisite, not optional
polish.

### 5.6 Threshold tuning fits the existing pattern — this part is not new work

The score cutoff, the `min_samples` cold-start gate, and any per-entity exemptions would slot
directly into the `BaseRule.DEFAULT_PARAMS`/`params`/`allowlist` mechanism already built for
the other 28 rules (`backend/app/detection/rules/base.py`) — no new config plumbing needed,
just a new rule class using the existing one.

### 5.7 Privacy

Feature snapshots derived from raw events inherit the same sensitivity the existing
[`backend_data_requirements_for_ml.md`](../backend_data_requirements_for_ml.md) already flags
for `parsed_data`/`raw_message` — a feature table keyed by username/IP is still identifying
data, even once it's been reduced to numbers.

## 6. Risks specific to a SOC tool

- **False positives read as credibility loss** for a security product faster than for most ML
  applications — an unexplained "anomaly" alert an analyst can't act on trains them to ignore
  the whole category. The evidence/explainability requirement in §4.5 and the shadow-mode
  rollout in §5.5 aren't optional polish.
- **Model drift**: normal behavior changes (new job duties, a host's workload changes) —
  needs a retraining cadence, and probably the same "don't let one exfiltration teach the
  model that exfiltration is normal" exclusion `egress_volume_anomaly.py` already applies to
  its own EWMA baseline.
- **Cold start abuse**: an attacker who's patient could establish "normal" behavior slowly
  enough to raise a new account/host's baseline before acting — a known weakness of any
  learned baseline, not unique to this implementation, worth naming rather than ignoring.

## 7. Open questions

- What deployment scale is actually expected? If this stays a small/demo deployment, the data
  volume in §3.3 never materializes and this stays infeasible regardless of engineering effort.
- Is an advisory-only alert (never auto-blocking, always paired with evidence) an acceptable
  bar for a first version?
- Who owns retraining operations once this exists — a manual admin action, or is a real
  scheduler worth adding for this reason (it would also unblock `host_log_silence` doing
  proactive checks)?
