import test from "node:test";
import assert from "node:assert/strict";
import {
  getAlertRecommendations,
  getIncidentActionLabel,
  incidentMatchesAlert,
} from "../src/soc/utils/alertRecommendations.js";

test("maps supported alert types to response recommendations", () => {
  assert.match(getAlertRecommendations({ ruleId: "R-101" })[0], /block the source ip/i);
  assert.match(getAlertRecommendations({ ruleName: "Invalid account enumeration" })[0], /investigate the source ip/i);
  assert.match(getAlertRecommendations({ title: "Repeated sudo failures" })[1], /mfa/i);
  assert.match(getAlertRecommendations({ title: "Suspicious successful login" })[0], /lock the affected account/i);
  assert.deepEqual(getAlertRecommendations({ title: "Unclassified anomaly" }), []);
});

test("matches linked incidents by authoritative alert ID before evidence", () => {
  const alert = { sourceAlertId: 42, evidenceIds: ["EVT-1"] };
  assert.equal(incidentMatchesAlert({ sourceAlertId: 42, eventIds: [] }, alert), true);
  assert.equal(incidentMatchesAlert({ sourceAlertId: 43, eventIds: ["EVT-1"] }, alert), false);
  assert.equal(incidentMatchesAlert({ sourceAlertId: null, eventIds: ["EVT-1"] }, { sourceAlertId: null, evidenceIds: ["EVT-1"] }), true);
});

test("labels incident actions from linkage, lifecycle, and severity", () => {
  assert.equal(getIncidentActionLabel({ status: "open" }, "critical"), "Go to incident · Open");
  assert.equal(getIncidentActionLabel({ status: "investigating" }, "high"), "Go to incident · Investigating");
  assert.equal(getIncidentActionLabel({ status: "resolved" }, "high"), "View incident · Resolved");
  assert.equal(getIncidentActionLabel({ status: "false positive" }, "critical"), "View incident · False Positive");
  assert.equal(getIncidentActionLabel(null, "high"), "Promote to incident");
  assert.equal(getIncidentActionLabel(null, "medium"), "Create incident");
});
