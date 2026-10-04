import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import {
  buildAnomalyStat,
  buildMlInsight,
  countAnomalyAlerts,
  describeModelStatus,
  formatDecisionScore,
  isLearnedAnomalyRule,
} from "../src/soc/utils/mlInsight.js";

// Evidence exactly as the backend's behavioral_anomaly_* rules write it.
const loginAlert = {
  rule: "behavioral_anomaly_login",
  evidence: {
    score: -0.1534,
    threshold: -0.02,
    feature_deviations: [
      { feature: "hour_cos", value: 0.9659, z_score: 2.14 },
      { feature: "is_new_geo", value: 1, z_score: -1.3 },
    ],
    model_version: 3,
    model_sample_count: 312,
    model_trained_at: "2026-10-01T12:34:56+00:00",
  },
};

test("shows the backend's native signed decision score with no rescaling", () => {
  assert.equal(formatDecisionScore(-0.1534), "-0.153");
  assert.equal(formatDecisionScore(0.104), "0.104");
  assert.equal(formatDecisionScore(-0.02), "-0.020");
  assert.equal(formatDecisionScore(null), "—");
  assert.equal(formatDecisionScore("not a number"), "—");
});

test("a negative score is kept negative, never clamped into a 0-100 range", () => {
  const insight = buildMlInsight(loginAlert);
  assert.equal(insight.score, -0.1534);
  assert.equal(insight.scoreText, "-0.153");
  assert.equal(insight.threshold, -0.02);
  assert.equal(insight.thresholdText, "-0.020");
  assert.equal(insight.belowThreshold, true);
  assert.ok(!JSON.stringify(insight).includes("/100"), "no 0-100 wording anywhere in the insight");
});

test("lists the real feature deviations and the model's provenance", () => {
  const insight = buildMlInsight(loginAlert);
  assert.deepEqual(insight.factors, [
    "hour_cos +2.1 SD (value 0.97)",
    "is_new_geo -1.3 SD (value 1.00)",
  ]);
  assert.deepEqual(insight.model, { version: 3, sampleCount: 312, trainedAt: "2026-10-01T12:34:56+00:00" });
});

test("applies to all three learned-anomaly rules and to nothing else", () => {
  for (const rule of ["behavioral_anomaly_login", "behavioral_anomaly_egress", "behavioral_anomaly_threat_log"]) {
    assert.equal(isLearnedAnomalyRule(rule), true);
    assert.ok(buildMlInsight({ ...loginAlert, rule }));
  }
  assert.equal(buildMlInsight({ ...loginAlert, rule: "brute_force_login" }), null);
  assert.equal(isLearnedAnomalyRule("egress_volume_anomaly"), false, "the statistical rule has no model score");
});

test("returns null instead of inventing a score when evidence is missing or malformed", () => {
  assert.equal(buildMlInsight(null), null);
  assert.equal(buildMlInsight({ rule: "behavioral_anomaly_login" }), null);
  assert.equal(buildMlInsight({ rule: "behavioral_anomaly_login", evidence: {} }), null);
  assert.equal(buildMlInsight({ rule: "behavioral_anomaly_login", evidence: { score: null } }), null);
  assert.equal(buildMlInsight({ rule: "behavioral_anomaly_login", evidence: { score: "abc" } }), null);
});

test("tolerates a missing threshold and ignores malformed deviations", () => {
  const insight = buildMlInsight({
    rule: "behavioral_anomaly_egress",
    evidence: { score: -0.05, feature_deviations: [{ feature: "log_bytes_out" }, { z_score: 3 }, null] },
  });
  assert.equal(insight.threshold, null);
  assert.equal(insight.thresholdText, null);
  assert.equal(insight.belowThreshold, null);
  assert.deepEqual(insight.factors, []);
});

test("counts only learned-model alerts, using the engine rule key", () => {
  const alerts = [
    { engineRule: "behavioral_anomaly_login" },
    { engineRule: "behavioral_anomaly_threat_log" },
    { engineRule: "brute_force_login" },
    { engineRule: "egress_volume_anomaly" },
    {},
  ];
  assert.equal(countAnomalyAlerts(alerts), 2);
  assert.equal(countAnomalyAlerts(null), 0);
});

test("reports real model status, and honest fallbacks when there is none or it can't be fetched", () => {
  assert.equal(describeModelStatus(null), "Model status unavailable");
  assert.equal(describeModelStatus(undefined), "Model status unavailable");
  assert.equal(describeModelStatus([]), "No model trained yet: rules are collecting data");
  assert.equal(
    describeModelStatus([{ feature_set: "login_behavior", version: 1, sample_count: 80, is_active: false }]),
    "No model trained yet: rules are collecting data",
    "an inactive (rolled-back) version is not the live model",
  );
  assert.equal(
    describeModelStatus([
      { feature_set: "login_behavior", version: 2, sample_count: 312, is_active: true, trained_at: "2026-10-01T12:00:00+00:00" },
      { feature_set: "threat_log", version: 1, sample_count: 90, is_active: true, trained_at: "2026-09-20T08:00:00+00:00" },
      { feature_set: "login_behavior", version: 1, sample_count: 80, is_active: false, trained_at: "2026-09-10T08:00:00+00:00" },
    ]),
    "login_behavior v2 (312 samples), threat_log v1 (90 samples) · latest trained 2026-10-01",
  );
});

test("the dashboard card combines the real alert count with the real model status", () => {
  assert.deepEqual(
    buildAnomalyStat([{ engineRule: "behavioral_anomaly_login" }], []),
    { label: "Anomaly alerts", value: "1", trend: "No model trained yet: rules are collecting data" },
  );
  assert.deepEqual(
    buildAnomalyStat([], null),
    { label: "Anomaly alerts", value: "0", trend: "Model status unavailable" },
  );
});

// ---- static guards: keep fabricated claims from quietly coming back ----------

const here = path.dirname(fileURLToPath(import.meta.url));
const read = (relative) => readFileSync(path.join(here, "..", relative), "utf8");

test("no anomaly/risk surface renders a 0-100 score or the removed RiskMeter", () => {
  const surfaces = [
    "src/soc/pages/AlertsPage.jsx",
    "src/soc/pages/EventLogsPage.jsx",
    "src/soc/pages/QuickResolvePage.jsx",
    "src/soc/pages/AiAnalysisPage.jsx",
    "src/soc/components/Ui.jsx",
    "src/soc/utils/mlInsight.js",
    "src/data/securityContent.js",
  ];
  for (const file of surfaces) {
    const text = read(file);
    assert.ok(!/RiskMeter|riskScore|anomaly_score/.test(text), `${file} still references a 0-100 risk/anomaly score`);
    assert.ok(!/\}\/100|[0-9]\/100/.test(text), `${file} renders a "/100" score`);
  }
});

test("the 14-day baseline and auto-promotion claims are gone from the demo data", () => {
  const demo = read("src/soc/data/mockData.js");
  assert.ok(!/14 days/.test(demo));
  assert.ok(!/AI anomalies flagged/.test(demo));
  assert.ok(!/30-day baseline/.test(demo));
  assert.ok(!/auto-?promot/i.test(demo));
});

test("connected mode can never return the canned sample analysis", () => {
  const source = read("src/soc/services/socRepository.js");
  const connected = source.slice(source.indexOf('mode: "api"'));
  assert.ok(connected.length > 0, "found the connected repository");
  assert.ok(!connected.includes("aiAnalysisSeed"), "the connected repository must not use the canned analysis");
  assert.match(connected, /runAiAnalysis\(\) \{\s*[^}]*throw new Error/);
});
