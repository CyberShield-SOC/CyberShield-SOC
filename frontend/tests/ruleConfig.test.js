import test from "node:test";
import assert from "node:assert/strict";
import {
  describeLiveConfig,
  detectionRuleApiBody,
  draftFromLive,
  editableFields,
  evidenceEntries,
  parseAllowlist,
  updatesFromDraft,
} from "../src/soc/utils/ruleConfig.js";

const ALLOWLIST_RULE = {
  engineKey: "service_account_interactive",
  tunables: ["enabled", "confidence", "cooldown_seconds", "allowlist"],
  defaultParams: {},
  enabled: true,
  cooldownSeconds: 0,
  confidence: 70,
  allowlist: ["svc-backup"],
};

const WINDOW_RULE = {
  engineKey: "brute_force_login",
  tunables: ["enabled", "confidence", "cooldown_seconds", "threshold", "window_seconds"],
  defaultParams: {},
  enabled: true,
  threshold: 5,
  windowSeconds: 60,
  cooldownSeconds: null,
  confidence: 80,
};

const PARAMS_RULE = {
  engineKey: "dns_tunneling",
  tunables: ["enabled", "confidence", "cooldown_seconds", "threshold", "window_seconds", "allowlist"],
  defaultParams: { min_subdomain_length: 30, min_entropy: 3.5 },
  enabled: true,
  threshold: 20,
  windowSeconds: 600,
  cooldownSeconds: 3600,
  allowlist: [],
  params: { min_subdomain_length: 30, min_entropy: 3.5 },
};

test("editableFields only returns settings the rule's tunables report", () => {
  const fields = editableFields(WINDOW_RULE).map((field) => field.key);
  assert.deepEqual(fields, ["threshold", "windowSeconds", "cooldownSeconds", "confidence"]);
  assert.deepEqual(editableFields(ALLOWLIST_RULE).map((field) => field.key), ["cooldownSeconds", "confidence", "allowlist"]);
});

test("parseAllowlist trims, dedupes, and drops blanks from newline or comma input", () => {
  assert.deepEqual(parseAllowlist("alice\nbob\n\nalice, carol"), ["alice", "bob", "carol"]);
  assert.deepEqual(parseAllowlist(""), []);
});

test("draftFromLive seeds editable values and params as strings", () => {
  const draft = draftFromLive(PARAMS_RULE);
  assert.equal(draft.engineKey, "dns_tunneling");
  assert.equal(draft.values.threshold, "20");
  assert.equal(draft.values.allowlist, "");
  assert.equal(draft.params.min_entropy, "3.5");
});

test("updatesFromDraft rejects out-of-range numbers and reports only changed fields", () => {
  const draft = draftFromLive(WINDOW_RULE);
  draft.values.threshold = "99999";
  let result = updatesFromDraft(draft, WINDOW_RULE);
  assert.ok(result.errors.threshold);
  assert.deepEqual(result.updates, {});

  draft.values.threshold = "8";
  result = updatesFromDraft(draft, WINDOW_RULE);
  assert.deepEqual(result.errors, {});
  assert.deepEqual(result.updates, { threshold: 8 });
});

test("updatesFromDraft treats an empty required field as unset only when currently set", () => {
  const draft = draftFromLive(WINDOW_RULE);
  draft.values.windowSeconds = "";
  const result = updatesFromDraft(draft, WINDOW_RULE);
  assert.ok(result.errors.windowSeconds);
});

test("updatesFromDraft diffs the allowlist and rejects oversized entries", () => {
  const draft = draftFromLive(ALLOWLIST_RULE);
  draft.values.allowlist = "svc-backup\nsvc-deploy";
  let result = updatesFromDraft(draft, ALLOWLIST_RULE);
  assert.deepEqual(result.updates, { allowlist: ["svc-backup", "svc-deploy"] });

  draft.values.allowlist = "svc-backup";
  result = updatesFromDraft(draft, ALLOWLIST_RULE);
  assert.deepEqual(result.updates, {});

  draft.values.allowlist = "x".repeat(300);
  result = updatesFromDraft(draft, ALLOWLIST_RULE);
  assert.ok(result.errors.allowlist);
});

test("updatesFromDraft merges only changed params", () => {
  const draft = draftFromLive(PARAMS_RULE);
  draft.params.min_entropy = "4.0";
  const result = updatesFromDraft(draft, PARAMS_RULE);
  assert.deepEqual(result.updates.params, { min_entropy: 4 });
});

test("detectionRuleApiBody maps camelCase updates to the backend's snake_case PATCH body", () => {
  assert.deepEqual(
    detectionRuleApiBody({ threshold: 8, allowlist: ["a", "b"], params: { min_entropy: 4 } }),
    { threshold: 8, allowlist: ["a", "b"], params: { min_entropy: 4 } },
  );
  assert.deepEqual(detectionRuleApiBody({ enabled: false }), { enabled: false });
  assert.deepEqual(detectionRuleApiBody({}), {});
});

test("describeLiveConfig summarizes enabled state, fields, and params", () => {
  const summary = describeLiveConfig(WINDOW_RULE);
  assert.match(summary, /^Enabled/);
  assert.match(summary, /Threshold: 5/);
  assert.match(summary, /Window: 60/);
  assert.match(summary, /Confidence: 80/);
  assert.match(describeLiveConfig(PARAMS_RULE), /Min subdomain length: 30/);
  assert.equal(describeLiveConfig(null), "");
});

test("evidenceEntries formats scalars, lists, and nested objects while dropping empties", () => {
  const rows = evidenceEntries({
    destination_port: 22,
    distinct_hosts: 12,
    hosts_sample: ["10.0.0.1", "10.0.0.2"],
    reasons: [],
    bytes_out: 900_000_000,
    empty: null,
    prefix: "should be skipped",
    top_destinations: [{ destination: "1.2.3.4", bytes: 900_000_000 }],
  });
  const byKey = Object.fromEntries(rows.map((row) => [row.key, row.value]));
  assert.equal(byKey.destination_port, "22");
  assert.equal(byKey.hosts_sample, "10.0.0.1, 10.0.0.2");
  assert.equal(byKey.bytes_out, "900.0 MB");
  assert.ok(byKey.top_destinations.includes("1.2.3.4"));
  assert.equal("reasons" in byKey, false);
  assert.equal("empty" in byKey, false);
  assert.equal("prefix" in byKey, false);
});

test("evidenceEntries handles non-object input safely", () => {
  assert.deepEqual(evidenceEntries(null), []);
  assert.deepEqual(evidenceEntries([1, 2]), []);
});
