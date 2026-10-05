import test from "node:test";
import assert from "node:assert/strict";
import { httpRepository, incidentStatusOperation } from "../src/soc/services/socRepository.js";

test("completion uses one atomic request and reopening requires its own reason", () => {
  assert.deepEqual(incidentStatusOperation("resolved", { note: " Contained intrusion ", expectedVersion: 4 }), {
    suffix: "/resolve", method: "POST", body: { outcome: "RESOLVED", reason: "Contained intrusion", note: "Contained intrusion", expected_version: 4 },
  });
  assert.equal(incidentStatusOperation("false positive", { note: "Expected maintenance" }).body.outcome, "FALSE_POSITIVE");
  assert.throws(() => incidentStatusOperation("resolved"), /resolution note/);
  assert.throws(() => incidentStatusOperation("investigating", { reopen: true }), /reason/);
  assert.equal(incidentStatusOperation("investigating", { reopen: true, reason: "New source evidence" }).suffix, "/reopen");
});

test("older alert evidence uses every API page, captured context, and exact history", async () => {
  const previous = globalThis.fetch;
  const calls = [];
  const alert = { id: 42, upload_id: "old-upload", rule: "brute_force_login", title: "Older burst", severity: "HIGH", status: "REVIEWING", investigation_state: "INVESTIGATING", version: 3 };
  globalThis.fetch = async (url) => {
    calls.push(String(url));
    const path = new URL(String(url), "http://test");
    let payload;
    if (path.pathname.endsWith("/investigation")) payload = { alert, allowed_states: ["RESOLVED"] };
    else if (path.pathname.endsWith("/evidence")) payload = { events: [{ id: Number(path.searchParams.get("page")), source_filename: "old.csv", event_timestamp: null, raw_message: "preserved", normalized: { ip_address: "192.0.2.10", timestamp: null, status: "FAILED" } }], pagination: { page_count: 2 }, completeness: { complete: false } };
    else if (path.pathname.endsWith("/correlation-groups")) payload = { groups: [{ id: 7, entity_value: "192.0.2.10", reason: "Matching entity and rule", window_seconds: 60, counts: { events: 2 } }], pagination: { page_count: 1 } };
    else if (path.pathname.endsWith("/history")) payload = { events: [{ id: 8, occurred_at: "2026-01-01T12:00:00Z", event_type: "NOTE_ADDED", actor_name: "Analyst", note: "Verified original source", after: { version: 3 } }], next_after_id: null };
    else if (path.pathname.endsWith("/rule-context")) payload = { rule_context: { policy: { rule_key: "brute_force_login", window_seconds: 60 } } };
    else if (path.pathname.endsWith("/alerts")) payload = { alerts: [alert, { ...alert, id: 43 }], pagination: { page_count: 1 } };
    else throw new Error(`Unexpected request: ${url}`);
    return { ok: true, status: 200, json: async () => payload };
  };
  try {
    const result = await httpRepository.getAlertInvestigation("ALT-0042");
    assert.equal(result.events.length, 2);
    assert.equal(result.events[0].timestamp, ""); // Missing source time stays unknown.
    assert.equal(result.events[0].message, "preserved");
    assert.equal(result.related[0].alert.backendId, 43);
    assert.equal(result.related[0].timeWindow, "60 seconds (inclusive)");
    assert.equal(result.groups[0].ruleContext.policy.window_seconds, 60);
    assert.match(result.history[0].detail, /Verified original source/);
    assert.equal(result.completeness.complete, false);
    assert.ok(calls.some((url) => url.includes("/evidence?page=2")));
  } finally { globalThis.fetch = previous; }
});

test("completion attribution uses the resolution actor rather than the latest editor", async () => {
  const previous = globalThis.fetch;
  globalThis.fetch = async () => ({ ok: true, status: 200, json: async () => ({ incident: {
    id: 1, status: "RESOLVED", updated_by_user_id: 99, resolved_by_user_id: 7, resolved_by_name: "Resolver",
    resolved_at: "2026-01-01T12:00:00Z", resolution_reason: "Contained", resolution_note: "Verified evidence", version: 5,
  } }) });
  try {
    const result = await httpRepository.updateIncidentStatus("INC-0001", "resolved", { note: "Verified evidence" });
    assert.equal(result.completedByUserId, 7);
    assert.equal(result.completedBy, "Resolver");
    assert.equal(result.version, 5);
  } finally { globalThis.fetch = previous; }
});

test("false-positive alert updates use the canonical state API with a version guard", async () => {
  const previous = globalThis.fetch;
  globalThis.fetch = async (url, options) => {
    assert.equal(url, "/alerts/42/investigation");
    assert.equal(options.method, "PATCH");
    assert.deepEqual(JSON.parse(options.body), { state: "FALSE_POSITIVE", expected_version: 3 });
    return { ok: true, status: 200, json: async () => ({ alert: { id: 42, status: "CLOSED", investigation_state: "FALSE_POSITIVE", version: 4 } }) };
  };
  try {
    const result = await httpRepository.updateAlertStatus("ALT-0042", "false positive", 3);
    assert.equal(result.status, "false positive");
    assert.equal(result.version, 4);
  } finally { globalThis.fetch = previous; }
});
