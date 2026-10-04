# ML experiments: `behavioral_anomaly_threat_log` validation history

This directory holds the offline work behind IsolationForest pilot #3,
`behavioral_anomaly_threat_log` (`backend/app/detection/rules/behavioral_anomaly_threat_log.py`,
features in `backend/app/ml/features_threat_log.py`). It is kept separate
from `backend/tests/` because most of it is measurement, not pass/fail
regression testing — the pytest files under `backend/tests/test_ml_threat_log_*.py`
cover the stability guarantees; everything here is the evidence behind them.

Read top to bottom — each step is a response to what the previous one found.

## 1. Kaggle baseline: is there any signal at all? (ROC-AUC 0.72)

Five public anomaly-detection CSVs were evaluated as candidate training
data (`train_isolation_forest.py`, `reports/{advanced_cybersecurity,
embedded_system, kdd99, synthetic_traffic, threat_detection_logs}.txt`).
Only `cybersecurity_threat_detection_logs.csv` showed its label
(`threat_label`) correlated with observable traffic features at all —
ROC-AUC 0.72 using a per-row model with one-hot-encoded
protocol/action/user_agent and frequency-encoded IP/path columns. The
other four sat at or below random (ROC-AUC 0.35–0.50) and were dropped.
This justified building a pilot around this shape of data, but that
one-hot/per-row feature design is data-dependent (whatever categories
happen to appear in a training run) and can't be used as this pipeline's
fixed-width `feature_names` contract.

## 2. Production feature gap: the honest version is much weaker (ROC-AUC 0.53)

`eval_production_threat_log_features.py` re-derived the same CSV rows into
the production shape — a small, fixed feature set
(`log_bytes_total`, `connection_count`, `distinct_destinations`,
`distinct_ports`, `deny_rate`) bucketed hourly per source IP, the only
shape `features_threat_log.py` can commit to long-term. Evaluated the same
way, this dropped to **ROC-AUC ~0.53** — barely above chance
(`reports/threat_detection_logs_production_features.txt`). Most of the
one-hot model's power came from exactly the per-row categorical/frequency
signal the fixed schema can't carry.

## 3. The label-randomness finding: the baseline itself was confounded

Before chasing the gap further, the "any row in this bucket is non-benign"
label used throughout was checked for a cheap statistical artifact
(`reports/threat_detection_logs_label_fairness_check.txt`). Finding:
**`connection_count` alone — zero behavioral signal — reaches ROC-AUC
~0.66** against this label, because a bigger bucket has more chances to
contain a labeled row by chance; the empirical label rate by bucket size
tracks an iid-scatter prediction almost exactly. This confound sits under
every bucketed number in this directory equally (every feature set
compared includes `connection_count`), so relative comparisons between
feature sets stay meaningful, but no absolute ROC-AUC number here should be
read as "this much genuine behavioral signal." **This is also why the
Kaggle CSV was retired as a validation source** in favor of synthetic
ground truth (steps 5–7 below).

A follow-up add of rarity/novelty/entropy features, scored against this
same confounded CSV label, made things *worse* (ROC-AUC ~0.52,
`reports/threat_detection_logs_production_features_rarity.txt`) — further
evidence the CSV's destination/port/protocol/action values aren't actually
tied to its labels, not that the richer features are bad.

## 4. Per-IP history redesign

Despite the CSV not validating them, the richer features were kept as real
infrastructure: `features_threat_log.py` now computes `dest_rarity`,
`port_rarity`, `protocol_rarity`, `new_destination_rate`, `new_port_rate`,
`dest_entropy`, `port_entropy` — not from the current bucket alone, but
against each source IP's own running history (destination/port/protocol
frequency counts, capped to the 200 most-frequent values per dimension).
`behavioral_anomaly_threat_log.py` walks each upload's buckets in
chronological order *per source IP*, scoring every bucket against history
strictly before it (never against itself), and persists the updated
history via `entity_baselines` — the same mechanism
`first_seen_geo_asn`'s `known_geo` already uses. Cyclic hour/day-of-week
features were dropped entirely: every row in the Kaggle CSV carried
`hour=0`, so they were provably dead weight there, and removing them
changed nothing either way on that dataset (ROC-AUC 0.5358 → 0.5261 to
0.5198, within noise).

## 5. Attack injection: synthetic ground truth instead (6/6 separated)

`backend/tests/test_ml_threat_log_attack_injection.py` replaced the Kaggle
CSV with a synthetic scenario run through the real `/upload` endpoint:
establish 6 hours of ordinary history for a population of source IPs
(attack IPs included, indistinguishable from normal up to the point of
injection), train and activate a real model, then inject three attack
shapes — port scan, large transfer to a new destination, deny burst — in
both a loud and a subtle variant (6 total). Result: **all 6 attacks scored
below every normal IP, with no overlap** (normal range −0.056 to 0.104;
attack range −0.207 to −0.179 in that run). This is the test file's
permanent regression guarantee going forward.

## 6. Powered false-positive study (FP ≈ 0.8% per bucket)

The attack-injection test's 30-IP/1-seed population was good enough to
catch a gross failure but too small to trust an exact false-positive rate.
`threat_log_false_positive_power_check.py` reran the same scenario — real
production functions (`BehavioralAnomalyThreatLogRule.analyze()`,
`features_threat_log`, `pipeline`, `train_threat_detection.train()`)
called directly rather than through `/upload`, for speed — at **100 normal
IPs × 10 seeds × 4 ambient-novelty levels (0%, 5%, 15%, 30% of normal
buckets containing a destination that IP has never visited)**, plus
realistic confounds held constant across levels: occasional legitimate
volume spikes (100–300MB) and per-IP deny rates varying 5–20%. Full output
in `reports/threat_log_false_positive_powered.txt`.

| Novelty | Pooled FP rate @ −0.12 | 95% Wilson CI | Loud detect (30/30) | Subtle detect (30/30) | ROC-AUC |
|---|---|---|---|---|---|
| 0% | 0.90% (9/1000) | [0.47%, 1.70%] | 100% [88.7%, 100%] | 100% [88.7%, 100%] | 0.9999 |
| 5% | 0.80% (8/1000) | [0.41%, 1.57%] | 100% [88.7%, 100%] | 100% [88.7%, 100%] | 0.9999 |
| 15% | 0.80% (8/1000) | [0.41%, 1.57%] | 100% [88.7%, 100%] | 100% [88.7%, 100%] | 1.0000 |
| 30% | 0.70% (7/1000) | [0.34%, 1.44%] | 100% [88.7%, 100%] | 100% [88.7%, 100%] | 1.0000 |

Each detection cell is 30 attack instances (3 types × 10 seeds) and shows the
95% Wilson CI. A 30/30 result can still be as low as 88.7%. The CIs cover only
sampling error in this synthetic population. They do not say how realistic
the attacks are. The generator makes the attacks separable by construction (see the
caveat at the end of §7), so these detection rates are not evidence of
detection on real traffic.

FP rate is flat (even slightly lower) as ambient novelty rises — more
organic history gives the model a richer baseline rather than more false
alarms. Cause breakdown across the 32 total false positives, counted per
occurrence (a false positive with two causes counts toward both):
`volume_spike` 16, `elevated_deny_rate` 12, `new_destination` 12,
`no_obvious_cause` 4. These are attributions from the injected generator
labels, not a causal test of what the model responded to. Multiple causes
overlap more at higher novelty. Within that caveat, novelty does not look like
the dominant driver: volume spikes and deny-rate variance account for as many
false positives as novel destinations do.

## 7. Threshold sensitivity

Same powered run, pooled across all levels/seeds, scored at four candidate
thresholds:

| Threshold | FP rate | Loud detect (95% CI) | Subtle detect (95% CI) |
|---|---|---|---|
| −0.10 | 1.70% | 100% (120/120) [96.9%, 100%] | 100% (120/120) [96.9%, 100%] |
| **−0.12 (chosen)** | **0.80%** | **100% (120/120) [96.9%, 100%]** | **100% (120/120) [96.9%, 100%]** |
| −0.15 | 0.12% | 100% (120/120) [96.9%, 100%] | 95.8% (115/120) [90.6%, 98.2%] |
| −0.18 | 0.00% | 98.3% (118/120) [94.1%, 99.5%] | 90.8% (109/120) [84.3%, 94.8%] |

The threshold table pools all 4 novelty levels, so each class has 120
instances (4 levels × 10 seeds × 3 types). The threshold was chosen from this
same synthetic population, so these rates are in-sample. There is no held-out
threshold check.

−0.12 is the last point where subtle-attack detection is still 100% —
tightening further trades subtle (then loud) detection for diminishing FP
gains.

**Caveat — what these detection numbers do and do not show.** The attack
generator in `backend/tests/anomaly_eval/synthetic_threat_log.py` builds each
attack IP with one destination and attack ports outside the normal 80/443
set, while normal IPs use 2–3 core destinations. One feature alone, the count
of distinct destinations, separates the two classes at AUC ≈ 0.95–0.98 on
single seeds (checked with a single-feature AUC, not the model). The reported
ROC-AUC of 0.9999–1.0000 therefore mostly reflects that construction. The
result is a sanity check that the pipeline runs and catches obviously
out-of-pattern traffic. It is not a measure of how well the model would catch
realistic attacks on real traffic. This is why `-0.12` was chosen as the shipped default (see
`backend/app/detection/rules/behavioral_anomaly_threat_log.py`'s
`DEFAULT_PARAMS`).

## 8. Exfil-to-popular-destination result (guard case for future work)

A 500MB transfer to a destination already used by other normal IPs (mean
popularity 24/100 IPs at the 30% novelty level) was injected alongside the
powered run as a forward-looking guard case. **Flagged 40/40 (100%)**
across every level and seed, scoring −0.17 to −0.24 regardless of how
popular the destination had actually become. Confirms the current
features are blind to cross-organization popularity (expected — nothing
in `features_threat_log.py` tracks it yet), and is the number any future
rarity-weighting change must not erase.

## Limitations

- **All of this is synthetic traffic.** Every number above comes from a
  generated population (fixed core destination pools, parameterized
  novelty/spike/deny-rate probabilities, fixed RNG seeds). It demonstrates
  the feature design behaves sensibly under a plausible traffic model, not
  that it will behave the same way against a real deployment's actual
  logs. Real shadow-mode data (`GET /ml/scores`) is the only true
  validation once this rule is live.
- **The false-positive math is per-bucket, not per-IP-per-day or
  per-analyst-alert.** 0.8% per hourly bucket compounds over a day: an IP
  active most hours could accumulate multiple flagged buckets even if any
  single bucket's false-positive chance is low. shadow_mode's own review
  step (`GET /ml/scores`) is what currently absorbs that, not the
  per-bucket rate itself — this number should not be read as "0.8% of IPs
  get a false alert per day."
- **Margin pressure is real even though the headline rate is low.**
  ~4–4.6% of normal IPs land within 0.05 of the −0.12 threshold at every
  novelty level. The false-positive rate is stable, but the model isn't
  comfortably far from it — a different population, a noisier real
  deployment, or small drift in traffic patterns could move that 4% band
  across the line in either direction. Worth re-checking after real
  shadow-mode data accumulates, not assuming this margin holds indefinitely.

## Future work (not implemented — pending approval)

Three fixes were proposed in response to the false-positive measurements
above. None are implemented; FP rate was judged low enough (0.7–0.9%,
stable Wilson CI, zero detection loss) not to require one yet.

1. **Org-wide rarity weighting** — weight `dest_rarity`/`new_destination_rate`
   (etc.) by how many source IPs across the whole organization have used a
   destination, not just this one IP's own history, so a site many IPs use
   is treated as less suspicious than one nobody has ever touched.
   **Constraint if implemented: `log_bytes_total`, `connection_count`, and
   `deny_rate` must stay entirely independent of any rarity weighting** —
   only the `*_rarity`/`new_*_rate`/`*_entropy` features should be touched.
   This is what keeps the exfil-to-popular-destination case (§8) detectable
   after the change: that attack's signal lives in volume, not destination
   novelty. Validate by rerunning `threat_log_false_positive_power_check.py`
   unchanged and confirming the exfil case still flags ~100% while FP rate
   drops further at the higher novelty levels.
2. **Scale by amount of novelty, not binary presence** — a bucket with one
   new destination out of five connections and a bucket with twenty-five
   new ports currently rely on the IsolationForest to learn the
   magnitude difference; encoding it directly (e.g. novel-count-aware
   scaling) might separate "visited one new site" from "scanned 25 ports"
   more cleanly.
3. **Per-IP threshold calibration** — one global `score_threshold` assumes
   every source IP has equally variable "normal." An IP with naturally
   bursty behavior (higher baseline deny rate, frequent novelty) would
   calibrate a more lenient threshold than a quiet one. Most invasive of
   the three (per-entity state beyond the current pooled-model design) —
   validate against a mixed-variability population before recommending it.

## Datasets (not in the repository)

The five public CSVs behind §1-3 are **not tracked** and are not needed by
`backend/tests/` or CI. The folder was about 924 MB (one file alone is 874 MB),
so it can never be committed; it used to sit inside the repo directory (and
therefore inside OneDrive) and was moved out to a local folder, by default
`~/datasets/cybershield-anomaly-detection`. The two scripts that read it
(`train_isolation_forest.py`, `eval_production_threat_log_features.py`) are kept
as **historical provenance**: their results are frozen in `reports/`, and they
exit with a clear message if the data is absent. Point them at a copy with the
`CYBERSHIELD_DATASET_DIR` environment variable.

No Kaggle source URL was recorded when the files were first downloaded, and a
search could not confirm one for the large file, so treat it as irreplaceable
unless you can identify the original. To check that a re-download is the same
file, compare against this fingerprint:

| File | Size (bytes) | Notes |
| --- | --- | --- |
| `cybersecurity_threat_detection_logs.csv` | 874,358,689 | 6,000,001 lines incl. header; SHA-256 `D9F8FC863A68DB9A06F9EB49DDD86F72CCE63FA0EE7CF96C80F51B8E775A32BB`; columns `timestamp,source_ip,dest_ip,protocol,action,threat_label,log_type,bytes_transferred,user_agent,request_path` |
| `advanced_cybersecurity_data.csv` | 638,918 | |
| `embedded_system_network_security_dataset.csv` | 164,004 | |
| `corrected.gz.zip` | 1,290,657 | KDD-99 |
| `synthetic_network_traffic.csv.zip` | 92,188,700 | |

The accuracy validation that CI can actually run is synthetic and in-repo:
`backend/tests/anomaly_eval/` (see its README) and, for threat-log,
`backend/tests/test_ml_threat_log_*.py`.

## Where things live

- `train_isolation_forest.py` — the original 5-dataset offline evaluation (§1).
- `eval_production_threat_log_features.py` — production-feature-shape eval against the Kaggle CSV (§2–3).
- `threat_log_false_positive_power_check.py` — the powered synthetic study (§6–8); rerun with
  `backend/.venv/Scripts/python.exe ml_experiments/threat_log_false_positive_power_check.py`.
  Writes only to `reports/`; never commits to the real database (see the script's own docstring).
- `backend/tests/test_ml_threat_log_attack_injection.py` — permanent regression test (§5).
- `backend/tests/test_ml_threat_log_false_positive_check.py` — small/fast pytest version of §6
  (30 IPs × 1 seed, for CI; the powered version above is the one with real statistical weight).
- `reports/` — every text report cited above.
