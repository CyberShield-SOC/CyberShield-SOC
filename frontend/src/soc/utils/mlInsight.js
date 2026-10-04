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

/** The backend's native score, three decimals, no rescaling (e.g. "-0.153"). */
export function formatDecisionScore(value) {
  const number = Number(value);
  return value !== null && value !== "" && Number.isFinite(number) ? number.toFixed(3) : "—";
}

function formatDeviation(deviation) {
  const z = Number(deviation?.z_score);
  const value = Number(deviation?.value);
  if (!deviation?.feature || !Number.isFinite(z)) return null;
  const valueText = Number.isFinite(value) ? ` (value ${value.toFixed(2)})` : "";
  return `${deviation.feature} ${z >= 0 ? "+" : ""}${z.toFixed(1)} SD${valueText}`;
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
  if (evidence.score === null || evidence.score === undefined || !Number.isFinite(score)) return null;
  const hasThreshold = evidence.threshold !== null && evidence.threshold !== undefined && Number.isFinite(Number(evidence.threshold));
  const threshold = hasThreshold ? Number(evidence.threshold) : null;
  const deviations = Array.isArray(evidence.feature_deviations) ? evidence.feature_deviations : [];
  return {
    score,
    scoreText: formatDecisionScore(score),
    threshold,
    thresholdText: hasThreshold ? formatDecisionScore(threshold) : null,
    belowThreshold: hasThreshold ? score < threshold : null,
    factors: deviations.map(formatDeviation).filter(Boolean),
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
  const latest = active.map((model) => String(model.trained_at || "")).filter(Boolean).sort().at(-1);
  return `${parts.join(", ")}${latest ? ` · latest trained ${latest.slice(0, 10)}` : ""}`;
}

/** Dashboard card: real count of learned-model alerts plus real model status. */
export function buildAnomalyStat(alerts, models) {
  return {
    label: "Anomaly alerts",
    value: String(countAnomalyAlerts(alerts)),
    trend: describeModelStatus(models),
  };
}
