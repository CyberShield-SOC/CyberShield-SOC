import test from "node:test";
import assert from "node:assert/strict";
import {
  formatEvidenceValue,
  investigationHistoryForIncident,
  normalizedEvidenceRows,
  rawEvidenceRows,
  relatedAlertsForAlert,
} from "../src/soc/utils/investigationViews.js";

test("separates normalized event fields from preserved raw alert evidence", () => {
  const event = {
    timestamp: "2026-07-16T14:32:09Z",
    source: "auth.log",
    sourceIp: "203.0.113.88",
    user: "root",
    event: "Failed SSH login",
    severity: "critical",
    status: "failed",
    rule: "R-101",
    message: "raw line",
  };
  const alert = { evidence: { failed_count: 47, users: ["root", "admin"] } };

  assert.deepEqual(normalizedEvidenceRows(event).map(([key]) => key), [
    "Timestamp",
    "Source",
    "Source IP",
    "User",
    "Event",
    "Severity",
    "Status",
    "Rule",
  ]);
  assert.deepEqual(rawEvidenceRows(alert, event), [
    ["failed_count", 47],
    ["users", ["root", "admin"]],
    ["raw_message", "raw line"],
  ]);
  assert.equal(formatEvidenceValue(["root", "admin"]), "root, admin");
});

test("finds related alerts by shared entity inside the correlation window without duplicates", () => {
  const selected = {
    id: "ALT-1",
    sourceIp: "203.0.113.88",
    user: "root",
    ruleId: "R-101",
    observedAt: "2026-07-16T14:32:09Z",
    evidenceIds: ["EVT-1"],
  };
  const related = relatedAlertsForAlert(selected, [
    selected,
    { id: "ALT-2", title: "Enumeration", severity: "high", sourceIp: "203.0.113.88", user: "admin", ruleId: "R-102", observedAt: "2026-07-16T14:20:09Z", evidenceIds: ["EVT-2"] },
    { id: "ALT-3", title: "Old event", severity: "low", sourceIp: "203.0.113.88", user: "root", ruleId: "R-101", observedAt: "2026-07-16T10:20:09Z", evidenceIds: ["EVT-3"] },
  ], [{ id: "EVT-2" }]);

  assert.equal(related.length, 1);
  assert.equal(related[0].alert.id, "ALT-2");
  assert.equal(related[0].groupingEntity, "203.0.113.88");
  assert.equal(related[0].linkedEvents.length, 1);
});

test("combines incident status and analyst note history in newest-first order", () => {
  const history = investigationHistoryForIncident(
    { id: "INC-1", status: "resolved", updated: "2026-07-16T14:00:00Z", completedAt: "2026-07-16T15:00:00Z", completedBy: "Analyst" },
    [{ id: "NOTE-1", title: "Validated host", author: "Analyst", linkedType: "incident", linkedId: "INC-1", updatedAt: "2026-07-16T14:30:00Z", archived: false }],
  );

  assert.deepEqual(history.map((item) => item.title), ["Resolved", "Validated host", "Incident record available", "Status: resolved"]);
});
