# Feasibility: `sklearn.ensemble.IsolationForest` for anomaly detection

Scoped answer to one question: could CyberShield use `IsolationForest` to catch things the
28 rule-based detectors (`backend/app/detection/rules/`) miss, and if so, what data would it
need? This is a feasibility note, not an implementation — nothing here is wired into the
engine. It complements, and does not replace,
[`docs/backend_data_requirements_for_ml.md`](../backend_data_requirements_for_ml.md), which
predates the Group A/B/C rule work and the `entity_baselines`/`host_heartbeats`/
`threat_indicators` tables described below.

## Verdict

**Feasible as a complementary, advisory scoring layer. Not implementable today as-is.**
Three concrete things are missing before it could run for real: a persisted per-entity
**feature history** (today's baselines are running scalars, not stored feature vectors — see
§3.2), enough **event volume per entity** to fit a model on, and a **training job outside the
request path** (detection today runs synchronously inside `/upload`, and fitting a forest is
too slow to do per-upload). None of these are hard blockers, but none exist yet either.

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

## 5. Risks specific to a SOC tool

- **False positives read as credibility loss** for a security product faster than for most ML
  applications — an unexplained "anomaly" alert an analyst can't act on trains them to ignore
  the whole category. The evidence/explainability requirement in §4.5 isn't optional polish.
- **Model drift**: normal behavior changes (new job duties, a host's workload changes) —
  needs a retraining cadence, and probably the same "don't let one exfiltration teach the
  model that exfiltration is normal" exclusion `egress_volume_anomaly.py` already applies to
  its own EWMA baseline.
- **Cold start abuse**: an attacker who's patient could establish "normal" behavior slowly
  enough to raise a new account/host's baseline before acting — a known weakness of any
  learned baseline, not unique to this implementation, worth naming rather than ignoring.

## 6. Open questions

- What deployment scale is actually expected? If this stays a small/demo deployment, the data
  volume in §3.3 never materializes and this stays infeasible regardless of engineering effort.
- Is an advisory-only alert (never auto-blocking, always paired with evidence) an acceptable
  bar for a first version?
- Who owns retraining operations once this exists — a manual admin action, or is a real
  scheduler worth adding for this reason (it would also unblock `host_log_silence` doing
  proactive checks)?
