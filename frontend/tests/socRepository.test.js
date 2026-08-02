import test from "node:test";
import assert from "node:assert/strict";
import {
  apiAlertStatus,
  apiIncidentStatus,
  backendId,
  getRepositoryErrorMessage,
  normalizeWorkspaceUser,
} from "../src/soc/services/socRepository.js";

test("extracts only positive safe backend identifiers", () => {
  assert.equal(backendId("ALT-0042"), 42);
  assert.equal(backendId(12), 12);
  assert.equal(backendId("ALT-0"), null);
  assert.equal(backendId("invalid"), null);
});

test("normalizes backend user records without trusting malformed identities", () => {
  assert.deepEqual(normalizeWorkspaceUser({
    id: 7,
    username: " analyst7 ",
    email: "Analyst7@Example.com ",
    full_name: "Analyst Seven",
    is_active: true,
    role: "Analyst",
  }), {
    id: 7,
    username: "analyst7",
    email: "analyst7@example.com",
    fullName: "Analyst Seven",
    isActive: true,
    role: "Analyst",
  });
  assert.throws(() => normalizeWorkspaceUser({ id: 0, username: "", email: "" }), /invalid user record/i);
  assert.throws(() => normalizeWorkspaceUser({ id: 7, username: "user", email: "user@example.com", role: "Owner" }), /invalid user record/i);
});

test("does not silently coerce unsupported workflow statuses", () => {
  assert.equal(apiAlertStatus("investigating"), "REVIEWING");
  assert.equal(apiAlertStatus("unexpected"), null);
  assert.equal(apiIncidentStatus("open"), "OPEN");
  assert.equal(apiIncidentStatus("false positive"), "FALSE_POSITIVE");
  assert.equal(apiIncidentStatus("closed"), null);
  assert.equal(apiIncidentStatus("awaiting approval"), null);
});

test("maps API failures to bounded actionable messages", () => {
  assert.equal(
    getRepositoryErrorMessage(415, { detail: { error: "Unsupported log type." } }),
    "Unsupported log type.",
  );
  assert.match(getRepositoryErrorMessage(422), /submitted values were invalid/i);
  assert.match(getRepositoryErrorMessage(503), /temporarily unavailable/i);
});

test("the generic 415 fallback message lists every backend-accepted extension, including .txt", () => {
  // Regression guard: this fallback only shows when the backend response has
  // no detail.error, but it must still name every extension /upload actually
  // accepts (backend/app/middleware/file_validation.py's ALLOWED_EXTENSIONS)
  // so it doesn't quietly go stale the next time that list changes.
  const message = getRepositoryErrorMessage(415, {});
  for (const extension of [".log", ".csv", ".txt", ".json", ".jsonl"]) {
    assert.ok(message.includes(extension), `expected fallback 415 message to mention ${extension}`);
  }
});
