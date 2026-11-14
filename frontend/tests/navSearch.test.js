import test from "node:test";
import assert from "node:assert/strict";
import { resolveNavDestination } from "../src/soc/utils/navSearch.js";

const TARGETS = [
  ["dashboard", "Dashboard"],
  ["event-logs", "Event Logs"],
  ["alerts", "Alerts"],
  ["incidents", "Incidents"],
  ["incident-tracking", "Incident Tracking"],
  ["ai-analysis", "AI Analysis"],
  ["analyst-notes", "Analyst Notes"],
  ["reports", "Reports"],
  ["users", "Users"],
];

test("a whole label matches, singular or plural, before any word match", () => {
  assert.equal(resolveNavDestination("Alerts", TARGETS), "alerts");
  assert.equal(resolveNavDestination("alert", TARGETS), "alerts");
  assert.equal(resolveNavDestination("incident", TARGETS), "incidents");
  assert.equal(resolveNavDestination("incidents", TARGETS), "incidents");
  assert.equal(resolveNavDestination("incident tracking", TARGETS), "incident-tracking");
  assert.equal(resolveNavDestination("user", TARGETS), "users");
});

test("a whole word of a multi-word label matches", () => {
  assert.equal(resolveNavDestination("tracking", TARGETS), "incident-tracking");
  assert.equal(resolveNavDestination("notes", TARGETS), "analyst-notes");
  assert.equal(resolveNavDestination("analysis", TARGETS), "ai-analysis");
  assert.equal(resolveNavDestination("logs", TARGETS), "event-logs");
});

test("substrings and short queries never match", () => {
  assert.equal(resolveNavDestination("port", TARGETS), null);
  assert.equal(resolveNavDestination("ale", TARGETS), null);
  assert.equal(resolveNavDestination("a", TARGETS), null);
  assert.equal(resolveNavDestination("", TARGETS), null);
  assert.equal(resolveNavDestination("10.0.0.5", TARGETS), null);
});

test("a section the viewer cannot open is not a destination", () => {
  const viewerCanAccess = (route) => route !== "users";
  assert.equal(resolveNavDestination("users", TARGETS, viewerCanAccess), null);
  assert.equal(resolveNavDestination("alerts", TARGETS, viewerCanAccess), "alerts");
});
