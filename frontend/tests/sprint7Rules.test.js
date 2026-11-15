import test from "node:test";
import assert from "node:assert/strict";
import { actionIsEnabled, customRuleUpdates, toggleRuleAction, validateCustomRuleDraft } from "../src/soc/utils/customRuleDraft.js";
import { describeRuleAction } from "../src/soc/utils/ruleActionResults.js";
import { alertDetectionMethod, buildMlInsight, formatDecisionScore } from "../src/soc/utils/mlInsight.js";
import { httpRepository, socRepository } from "../src/soc/services/socRepository.js";

const draft = { ruleName: "SSH failures", severity: "high", category: "generic_detection", groupBy: "ip_address", window: "10m", conditions: [{ field: "port", operator: "in", value: "22,443" }] };

test("validates custom rules before saving, including port bounds and empty lists", () => {
  assert.deepEqual(validateCustomRuleDraft(draft), { syntaxProblems: [], unknownFields: [] });
  for (const value of ["65536", "-1", "22,", "22.5", "22,not-a-port"]) {
    assert.ok(validateCustomRuleDraft({ ...draft, conditions: [{ field: "port", operator: "in", value }] }).syntaxProblems.length, value);
  }
  assert.ok(validateCustomRuleDraft({ ...draft, conditions: [] }).syntaxProblems.length);
  assert.ok(validateCustomRuleDraft({ ...draft, conditions: Array(11).fill(draft.conditions[0]) }).syntaxProblems.length);
  assert.deepEqual(validateCustomRuleDraft({ ...draft, conditions: [{ field: "unsupported", value: "x" }] }).unknownFields, ["unsupported"]);
});

test("validates minute precision, overnight ranges, timezones and required metadata", () => {
  const condition = { field: "timestamp", operator: "between", value: "23:45 – 01:15", timezone: "America/Chicago" };
  assert.equal(validateCustomRuleDraft({ ...draft, conditions: [condition] }).syntaxProblems.length, 0);
  for (const value of ["24:00 – 06:00", "01:60 – 02:00", "01:00 – 01:00", "bad"]) assert.ok(validateCustomRuleDraft({ ...draft, conditions: [{ ...condition, value }] }).syntaxProblems.length);
  assert.ok(validateCustomRuleDraft({ ...draft, conditions: [{ ...condition, timezone: "Invalid/Timezone" }] }).syntaxProblems.length);
  for (const patch of [{ ruleName: " " }, { category: "unknown" }, { severity: "extreme" }, { window: "7m" }, { groupBy: "unknown" }]) assert.ok(validateCustomRuleDraft({ ...draft, ...patch }).syntaxProblems.length);
});

test("nested action switches preserve thresholds, channels and playbook configuration", () => {
  const action = { enabled: true, threshold_count: 5, threshold_window_seconds: 600, playbook_id: "PB-04" };
  const disabled = toggleRuleAction(action, false);
  assert.equal(actionIsEnabled(disabled), false);
  assert.deepEqual(toggleRuleAction(disabled, true), action);
  assert.equal(actionIsEnabled(false), false);
  assert.equal(actionIsEnabled(undefined), false);
  assert.equal(actionIsEnabled({ threshold_count: 3 }), true);
});

test("rule updates preserve explicit clears and send only the changed fields", async () => {
  assert.deepEqual(customRuleUpdates({ status: "disabled" }), { status: "DISABLED" });
  const updates = { name: "Updated rule", category: "generic_detection", severity: "low", conditions: draft.conditions, groupBy: "none", windowSeconds: 300, tactic: null, dsl: null, actions: { notify_slack: false } };
  const previous = globalThis.fetch;
  globalThis.fetch = async (url, options) => {
    assert.equal(url, "/custom-rules/7");
    assert.equal(options.method, "PATCH");
    assert.deepEqual(JSON.parse(options.body), { name: "Updated rule", category: "generic_detection", severity: "LOW", conditions: draft.conditions, group_by: "none", window_seconds: 300, tactic: null, dsl: null, actions: { notify_slack: false } });
    return { ok: true, status: 200, json: async () => ({ rule: { id: 7, rule_id: "R-109", ...updates } }) };
  };
  try { assert.equal((await httpRepository.updateCustomRule(7, updates)).id, "R-109"); }
  finally { globalThis.fetch = previous; }
});

test("sample-mode edits retain conditions, grouping and nested action settings", async () => {
  const previous = globalThis.window;
  const storage = new Map();
  globalThis.window = { setTimeout, sessionStorage: { getItem: (key) => storage.get(key) || null, setItem: (key, value) => storage.set(key, value) } };
  try {
    assert.notEqual(socRepository.mode, "api");
    const created = await socRepository.createCustomRule({ name: "Original", category: "generic_detection", severity: "high", conditions: draft.conditions, groupBy: "ip_address", windowSeconds: 600, actions: { auto_incident: { enabled: false, threshold_count: 5 } }, status: "enabled" });
    const updated = await socRepository.updateCustomRule(created.backendId, { name: "Edited", severity: "low", groupBy: "username", windowSeconds: 300, conditions: [{ field: "username", operator: "equals", value: "alice" }] });
    assert.equal(updated.id, created.id); assert.equal(updated.name, "Edited");
    assert.equal(updated.groupBy, "username"); assert.equal(updated.windowSeconds, 300);
    assert.equal(updated.conditions[0].value, "alice"); assert.equal(updated.severity, "low");
    assert.deepEqual(updated.actions.auto_incident, { enabled: false, threshold_count: 5 });
    await socRepository.updateCustomRule(created.backendId, { status: "disabled" });
    const saved = (await socRepository.getCustomRules()).rules[0];
    assert.equal(saved.status, "disabled"); assert.equal(saved.conditions[0].value, "alice");
  } finally { globalThis.window = previous; }
});

test("action outcomes distinguish success, skipped, failed, thresholds and unknown states", () => {
  assert.equal(describeRuleAction("notify_slack", { status: "sent" }).tone, "ok");
  assert.match(describeRuleAction("notify_slack", { status: "skipped" }).text, /no webhook/);
  const failed = describeRuleAction("notify_slack", { status: "failed", error: "https://secret.example/token" });
  assert.equal(failed.tone, "error"); assert.doesNotMatch(failed.text, /secret/);
  assert.equal(describeRuleAction("auto_incident", { status: "created", incident_id: 12 }).incidentId, 12);
  assert.equal(describeRuleAction("auto_incident", { status: "already_exists", incident_id: 12 }).incidentId, 12);
  assert.doesNotMatch(describeRuleAction("auto_incident", { status: "created" }).text, /undefined|NaN/);
  assert.match(describeRuleAction("auto_incident", { status: "threshold_not_met", threshold_count: 3, threshold_window_seconds: 3600 }).text, /3 events within 1h/);
  assert.match(describeRuleAction("suggest_playbook", { status: "linked", playbook_id: "PB-02" }).text, /PB-02/);
  assert.match(describeRuleAction("new_action", { status: "pending" }).text, /pending/);
  assert.equal(describeRuleAction("bad", null), null);
});

test("ML and rule findings remain distinguishable without manufacturing scores", () => {
  assert.equal(alertDetectionMethod({ engineRule: "behavioral_anomaly_login" }), "ml");
  assert.equal(alertDetectionMethod({ engineRule: "brute_force_login" }), "rule");
  assert.equal(buildMlInsight({ rule: "brute_force_login", evidence: { score: -1 } }), null);
  for (const score of [null, "", " ", false, "bad"]) {
    assert.equal(buildMlInsight({ rule: "behavioral_anomaly_login", evidence: { score } }), null);
    assert.equal(formatDecisionScore(score), "—");
  }
  const result = buildMlInsight({ rule: "behavioral_anomaly_login", evidence: { score: 0, threshold: -0.02, feature_deviations: [{ feature: "count", z_score: null }] } });
  assert.equal(result.scoreText, "0.000"); assert.equal(result.belowThreshold, false); assert.deepEqual(result.factors, []);
});
