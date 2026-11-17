// Learned-anomaly display helpers.
//
// The backend scores events with scikit-learn's IsolationForest and reports the
// raw `decision_function` value: below 0 is anomalous, and lower (more negative)
// means more anomalous. Alerts are raised when the score falls below a
// per-rule threshold (about -0.02 for login/egress, -0.12 for threat log).
// There is NO 0-100 anomaly score, so nothing in this file converts to one:
// scores are always shown in the backend's native form.

export const ML_ANOMALY_RULE_PREFIX = "behavioral_anomaly_";

export const DECISION_SCORE_HELP =
  "Raw IsolationForest decision score: below 0 is anomalous, and lower (more negative) means more anomalous.";

export function isLearnedAnomalyRule(ruleKey) {
  return String(ruleKey || "").startsWith(ML_ANOMALY_RULE_PREFIX);
}

export function alertDetectionMethod(alert) {
  return isLearnedAnomalyRule(alert?.engineRule || alert?.rule) ? "ml" : "rule";
}

export function detectionMethodLabel(alert) {
  return alertDetectionMethod(alert) === "ml" ? "ML anomaly" : "Rule based";
}

function hasNumber(value) {
  return (typeof value === "number" || (typeof value === "string" && value.trim() !== "")) && Number.isFinite(Number(value));
}

/** The backend's native score, three decimals, no rescaling (e.g. "-0.153"). */
export function formatDecisionScore(value) {
  const number = Number(value);
  return hasNumber(value) ? number.toFixed(3) : "—";
}

/**
 * The API's { feature, value, z_score } rows (alert evidence and
 * GET /ml/anomalies alike) as { feature, value, zScore }, dropping rows
 * without a feature or a finite z-score. The one place that shape rule lives.
 */
export function normalizeDeviations(list) {
  return (Array.isArray(list) ? list : [])
    .filter((deviation) => deviation?.feature && hasNumber(deviation.z_score))
    .map((deviation) => ({
      feature: String(deviation.feature),
      value: hasNumber(deviation.value) ? Number(deviation.value) : null,
      zScore: Number(deviation.z_score),
    }));
}

function formatDeviation({ feature, value, zScore }) {
  const valueText = value === null ? "" : ` (value ${value.toFixed(2)})`;
  return `${feature} ${zScore >= 0 ? "+" : ""}${zScore.toFixed(1)} SD${valueText}`;
}

/**
 * Build the alert-detail insight from a raw API alert's `evidence`, which the
 * behavioral_anomaly_* rules fill with { score, threshold, feature_deviations,
 * model_version, model_sample_count, model_trained_at }. Returns null for any
 * other alert, so readers treat it as "no learned-model insight".
 */
export function buildMlInsight(rawAlert) {
  const evidence = rawAlert?.evidence;
  if (!isLearnedAnomalyRule(rawAlert?.rule) || !evidence || typeof evidence !== "object") return null;
  const score = Number(evidence.score);
  if (!hasNumber(evidence.score)) return null;
  const hasThreshold = hasNumber(evidence.threshold);
  const threshold = hasThreshold ? Number(evidence.threshold) : null;
  const deviations = normalizeDeviations(evidence.feature_deviations);
  return {
    score,
    scoreText: formatDecisionScore(score),
    threshold,
    thresholdText: hasThreshold ? formatDecisionScore(threshold) : null,
    belowThreshold: hasThreshold ? score < threshold : null,
    factors: deviations.map(formatDeviation),
    // The same deviations unformatted, for charting (see deviationBars).
    deviations,
    model: {
      version: evidence.model_version ?? null,
      sampleCount: evidence.model_sample_count ?? null,
      trainedAt: evidence.model_trained_at ?? null,
    },
  };
}

export function countAnomalyAlerts(alerts) {
  return (Array.isArray(alerts) ? alerts : []).filter((alert) => isLearnedAnomalyRule(alert?.engineRule)).length;
}

/**
 * One-line, real status of the trained models (from GET /ml/models).
 * `models` is the API list, or null when it could not be fetched.
 */
export function describeModelStatus(models) {
  if (!Array.isArray(models)) return "Model status unavailable";
  const active = models.filter((model) => model?.is_active);
  if (!active.length) return "No model trained yet: rules are collecting data";
  const parts = active.map((model) => `${model.feature_set} v${model.version} (${model.sample_count} samples)`);
  const latest = active
    .map((model) => new Date(model.trained_at || ""))
    .filter((date) => Number.isFinite(date.getTime()))
    .sort((a, b) => a - b)
    .at(-1);
  return `${parts.join(", ")}${latest ? ` · latest trained ${localDateStamp(latest)}` : ""}`;
}

// trained_at is UTC; slicing the string showed tomorrow's date to anyone west
// of UTC in the evening. Show the viewer's calendar day instead.
function localDateStamp(date) {
  const pad = (n) => String(n).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`;
}

/** Dashboard card: real count of learned-model alerts plus real model status. */
export function buildAnomalyStat(alerts, models) {
  return {
    label: "Anomaly alerts",
    value: String(countAnomalyAlerts(alerts)),
    trend: describeModelStatus(models),
  };
}

export const PILOT_LABELS = Object.freeze({
  login_behavior: "Login behavior",
  egress_volume: "Egress volume",
  threat_log: "Threat log",
});

export function pilotLabel(featureSet) {
  return PILOT_LABELS[featureSet] || String(featureSet || "").replace(/_/g, " ");
}

/**
 * Where one behavioral-anomaly pilot (from GET /ml/anomalies) sits in its
 * lifecycle, in words a Viewer can read without knowing the backend:
 *   collecting -> ready to train -> scoring in shadow mode -> alerting.
 * `status` matches the StatusBadge vocabulary used elsewhere in the UI.
 */
export function describePilotStage(pilot) {
  if (!pilot) return { key: "unknown", status: "disabled", label: "Unavailable", detail: "" };
  const { sampleCount = 0, minSamples = 0, activeModel, shadowMode, scoredCount = 0, ruleEnabled = true } = pilot;
  if (!activeModel) {
    if (sampleCount < minSamples) {
      const needed = Math.max(0, minSamples - sampleCount);
      return {
        key: "collecting",
        status: "pending",
        label: "Collecting samples",
        detail: `${sampleCount} of ${minSamples} samples stored. ${needed} more before a model can be trained.`,
      };
    }
    return {
      key: "ready",
      status: "pending",
      label: "Ready to train",
      detail: `${sampleCount} samples stored. An Admin can train the first model from the Threat Detection page.`,
    };
  }
  if (!ruleEnabled) {
    return { key: "disabled", status: "disabled", label: "Rule disabled", detail: "A model is trained, but the detection rule is switched off." };
  }
  if (shadowMode) {
    return {
      key: "shadow",
      status: "pending",
      label: "Shadow mode",
      detail: scoredCount
        ? `Model v${activeModel.version} has scored ${scoredCount} events. Findings are logged here, not raised as alerts, until an Analyst promotes the rule.`
        : `Model v${activeModel.version} is active and will score the next upload. Nothing scored yet.`,
    };
  }
  return {
    key: "live",
    status: "enabled",
    label: "Alerting",
    detail: `Model v${activeModel.version} raises alerts when a score falls below the threshold.`,
  };
}

/**
 * Horizontal-bar items for a list of {feature, value, zScore} deviations:
 * bar length is |z|, so the biggest driver is the longest bar, and the colour
 * says which direction it moved from the baseline.
 */
export function deviationBars(deviations) {
  return (Array.isArray(deviations) ? deviations : []).map((d) => ({
    label: d.value === null ? d.feature : `${d.feature} (${d.value.toFixed(2)})`,
    value: Math.abs(d.zScore),
    // Above the learned baseline vs below it: two hues of their own, so the
    // factor chart is not read as a severity.
    color: d.zScore < 0 ? "var(--chart-anomaly-below)" : "var(--chart-anomaly-above)",
  }));
}
