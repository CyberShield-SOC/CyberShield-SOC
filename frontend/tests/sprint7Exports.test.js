import test from "node:test";
import assert from "node:assert/strict";
import { previewReportRecordCount, REPORT_EXPORTERS, selectReportRecords } from "../src/soc/utils/reportExport.js";
import { downloadBlobFile } from "../src/soc/utils/eventUtils.js";

const NOW = new Date("2026-10-25T12:00:00Z");
const ids = (records) => records.map((record) => record.id);

test("Daily SOC operations covers only events from the last 24 hours (and legacy records with no timestamp)", () => {
  const events = [
    { id: "EVT-RECENT", timestamp: "2026-10-25T10:00:00Z" },
    { id: "EVT-OLD", timestamp: "2026-10-23T10:00:00Z" },
    { id: "EVT-LEGACY" },
  ];
  assert.deepEqual(ids(selectReportRecords("Daily SOC operations", { events }, NOW)).sort(), ["EVT-LEGACY", "EVT-RECENT"]);
});

test("Weekly incident summary covers only incidents updated in the last 7 days", () => {
  const incidents = [
    { id: "INC-RECENT", updated: "2026-10-24T00:00:00Z" },
    { id: "INC-OLD", updated: "2026-10-01T00:00:00Z" },
  ];
  assert.deepEqual(ids(selectReportRecords("Weekly incident summary", { incidents }, NOW)), ["INC-RECENT"]);
});

test("Detection coverage groups alerts into one entry per rule with severity counts and MITRE technique", () => {
  const alerts = [
    { id: "ALT-1", ruleId: "R-1", ruleName: "brute_force_login", severity: "high", firstSeen: "2026-10-20T00:00:00Z", lastSeen: "2026-10-24T00:00:00Z", mitreTechnique: "T1110.001" },
    { id: "ALT-2", ruleId: "R-1", ruleName: "brute_force_login", severity: "critical", firstSeen: "2026-10-22T00:00:00Z", lastSeen: "2026-10-25T00:00:00Z" },
    { id: "ALT-3", ruleId: "R-2", ruleName: "port_scan", severity: "low", firstSeen: "2026-10-23T00:00:00Z", lastSeen: "2026-10-23T00:00:00Z" },
  ];
  const rules = selectReportRecords("Detection coverage", { alerts }, NOW);
  assert.equal(rules.length, 2);
  assert.equal(rules[0].ruleName, "brute_force_login");
  assert.equal(rules[0].count, 2);
  assert.equal(rules[0].critical, 1);
  assert.equal(rules[0].high, 1);
  assert.equal(rules[0].mitreTechnique, "T1110.001");
  assert.equal(rules[0].firstSeen, "2026-10-20T00:00:00.000Z");
  assert.equal(rules[0].lastSeen, "2026-10-25T00:00:00.000Z");
});

test("Executive risk overview covers only open High/Critical incidents, highest priority first", () => {
  const incidents = [
    { id: "INC-LOW", priority: "low", status: "open", updated: "2026-10-25T00:00:00Z" },
    { id: "INC-HIGH", priority: "high", status: "investigating", updated: "2026-10-20T00:00:00Z" },
    { id: "INC-CRIT", priority: "critical", status: "open", updated: "2026-10-18T00:00:00Z" },
    { id: "INC-RESOLVED", priority: "critical", status: "resolved", updated: "2026-10-25T00:00:00Z" },
  ];
  assert.deepEqual(ids(selectReportRecords("Executive risk overview", { incidents }, NOW)), ["INC-CRIT", "INC-HIGH"]);
});

test("report scope is empty for unknown reports or missing data, never a throw", () => {
  for (const name of Object.keys(REPORT_EXPORTERS)) assert.deepEqual(selectReportRecords(name, {}, NOW), []);
  assert.deepEqual(selectReportRecords("unknown", { events: [{ id: "EVT-1" }] }, NOW), []);
  assert.equal(previewReportRecordCount("Daily SOC operations", {}), 0);
  assert.equal(previewReportRecordCount("Daily SOC operations", { events: [{ id: "EVT-1", timestamp: "2026-10-25T10:00:00Z" }] }, NOW), 1);
});

test("Daily SOC operations and Weekly incident summary anchor to the data's own recency, not wall-clock time (sample mode has frozen fixtures)", () => {
  const farFutureNow = new Date("2030-01-01T00:00:00Z");
  const events = [
    { id: "EVT-A", timestamp: "2026-07-16T13:36:32Z" },
    { id: "EVT-B", timestamp: "2026-07-16T14:32:09Z" },
  ];
  assert.equal(previewReportRecordCount("Daily SOC operations", { events }, farFutureNow), 2);
  const incidents = [
    { id: "INC-A", updated: "2026-07-16T13:00:00Z" },
    { id: "INC-B", updated: "2026-07-16T14:00:00Z" },
  ];
  assert.equal(previewReportRecordCount("Weekly incident summary", { incidents }, farFutureNow), 2);
});

test("downloads attach and remove their link and revoke URLs after success or failure", () => {
  const previous = { document: globalThis.document, window: globalThis.window, create: URL.createObjectURL, revoke: URL.revokeObjectURL };
  let removed = 0, revoked = 0, clicked = 0, timer;
  const link = { click() { clicked += 1; }, remove() { removed += 1; } };
  globalThis.document = { createElement: () => link, body: { append() {} } };
  globalThis.window = { setTimeout(callback) { timer = callback; } };
  URL.createObjectURL = () => "blob:test"; URL.revokeObjectURL = () => { revoked += 1; };
  try {
    assert.equal(downloadBlobFile(new Blob(["%PDF"]), "report.pdf"), "report.pdf");
    assert.equal(link.download, "report.pdf"); assert.equal(clicked, 1); assert.equal(removed, 1); assert.equal(revoked, 0);
    timer(); assert.equal(revoked, 1);
    link.click = () => { throw new Error("Download blocked"); };
    assert.throws(() => downloadBlobFile(new Blob(["%PDF"]), "report.pdf"), /Download blocked/);
    assert.equal(revoked, 2); assert.equal(removed, 2);
  } finally { globalThis.document = previous.document; globalThis.window = previous.window; URL.createObjectURL = previous.create; URL.revokeObjectURL = previous.revoke; }
});
