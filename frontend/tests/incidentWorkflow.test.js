import test from "node:test";
import assert from "node:assert/strict";
import {
  INCIDENT_STATUSES,
  incidentTerminalAction,
  incidentStatusLabel,
  isTerminalIncidentStatus,
  nextIncidentWorkflowAction,
  normalizeIncidentStatus,
} from "../src/soc/utils/incidentWorkflow.js";

test("defines one canonical four-state incident lifecycle", () => {
  assert.deepEqual(INCIDENT_STATUSES, ["open", "investigating", "resolved", "false positive"]);
  assert.equal(Object.isFrozen(INCIDENT_STATUSES), true);
});

test("normalizes and labels incident statuses safely", () => {
  assert.equal(normalizeIncidentStatus(" False Positive "), "false positive");
  assert.equal(incidentStatusLabel("false positive"), "False Positive");
  assert.equal(incidentStatusLabel(null), "Open");
});

test("recognizes terminal outcomes and supported next actions", () => {
  assert.equal(isTerminalIncidentStatus("RESOLVED"), true);
  assert.equal(isTerminalIncidentStatus("false positive"), true);
  assert.equal(isTerminalIncidentStatus("investigating"), false);
  assert.deepEqual(nextIncidentWorkflowAction("open"), ["investigating", "Start investigation"]);
  assert.deepEqual(nextIncidentWorkflowAction("investigating"), ["resolved", "Resolve incident"]);
  assert.equal(nextIncidentWorkflowAction("resolved"), null);
});

test("describes only terminal actions that require confirmation", () => {
  assert.equal(incidentTerminalAction("investigating"), null);
  assert.equal(incidentTerminalAction("resolved").confirmLabel, "Resolve incident");
  assert.equal(incidentTerminalAction(" FALSE POSITIVE ").confirmLabel, "Mark false positive");
});
