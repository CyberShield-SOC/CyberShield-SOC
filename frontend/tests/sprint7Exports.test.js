import test from "node:test";
import assert from "node:assert/strict";
import { createReportExport, previewReportRecordCount, REPORT_EXPORTERS } from "../src/soc/utils/reportExport.js";
import { downloadCsvFile, escapeCsvCell } from "../src/soc/utils/eventUtils.js";

const NOW = new Date("2026-10-25T12:00:00Z");

test("Daily SOC operations exports only events from the last 24 hours (and legacy records with no timestamp)", () => {
  const events = [
    { id: "EVT-RECENT", timestamp: "2026-10-25T10:00:00Z" },
    { id: "EVT-OLD", timestamp: "2026-10-23T10:00:00Z" },
    { id: "EVT-LEGACY" },
  ];
  const result = createReportExport("Daily SOC operations", { events }, NOW);
  assert.equal(result.recordCount, 2);
  assert.match(result.csv, /EVT-RECENT/);
  assert.match(result.csv, /EVT-LEGACY/);
  assert.doesNotMatch(result.csv, /EVT-OLD/);
  assert.match(result.filename, /^cybershield-daily-soc-operations-2026-10-25\.csv$/);
});

test("Weekly incident summary exports only incidents updated in the last 7 days", () => {
  const incidents = [
    { id: "INC-RECENT", updated: "2026-10-24T00:00:00Z", resolutionReason: "Contained", resolutionNote: "Verified original source" },
    { id: "INC-OLD", updated: "2026-10-01T00:00:00Z" },
  ];
  const result = createReportExport("Weekly incident summary", { incidents }, NOW);
  assert.equal(result.recordCount, 1);
  assert.match(result.csv, /INC-RECENT/);
  assert.match(result.csv, /Contained/);
  assert.doesNotMatch(result.csv, /INC-OLD/);
});

test("Detection coverage groups alerts into one row per rule with severity counts and MITRE technique", () => {
  const alerts = [
    { id: "ALT-1", ruleId: "R-1", ruleName: "brute_force_login", severity: "high", firstSeen: "2026-10-20T00:00:00Z", lastSeen: "2026-10-24T00:00:00Z", mitreTechnique: "T1110.001" },
    { id: "ALT-2", ruleId: "R-1", ruleName: "brute_force_login", severity: "critical", firstSeen: "2026-10-22T00:00:00Z", lastSeen: "2026-10-25T00:00:00Z" },
    { id: "ALT-3", ruleId: "R-2", ruleName: "port_scan", severity: "low", firstSeen: "2026-10-23T00:00:00Z", lastSeen: "2026-10-23T00:00:00Z" },
  ];
  const result = createReportExport("Detection coverage", { alerts }, NOW);
  assert.equal(result.recordCount, 2);
  const rows = result.csv.split("\n");
  assert.equal(rows.length, 3);
  assert.match(rows[1], /brute_force_login/);
  assert.match(rows[1], /T1110\.001/);
  assert.match(rows[1], /2026-10-20T00:00:00\.000Z/);
});

test("Executive risk overview exports only open High/Critical incidents, highest priority first", () => {
  const incidents = [
    { id: "INC-LOW", priority: "low", status: "open", updated: "2026-10-25T00:00:00Z" },
    { id: "INC-HIGH", priority: "high", status: "investigating", updated: "2026-10-20T00:00:00Z" },
    { id: "INC-CRIT", priority: "critical", status: "open", updated: "2026-10-18T00:00:00Z" },
    { id: "INC-RESOLVED", priority: "critical", status: "resolved", updated: "2026-10-25T00:00:00Z" },
  ];
  const result = createReportExport("Executive risk overview", { incidents }, NOW);
  assert.equal(result.recordCount, 2);
  assert.ok(result.csv.indexOf("INC-CRIT") < result.csv.indexOf("INC-HIGH"));
  assert.doesNotMatch(result.csv, /INC-LOW/);
  assert.doesNotMatch(result.csv, /INC-RESOLVED/);
});

test("every report produces a dated filename and rejects unknown reports or an empty source", () => {
  for (const name of Object.keys(REPORT_EXPORTERS)) {
    assert.throws(() => createReportExport(name, {}, NOW), new RegExp(`No ${REPORT_EXPORTERS[name].key} are available`));
  }
  assert.throws(() => createReportExport("unknown", {}, NOW), /supported report/);
  assert.throws(() => createReportExport("Executive risk overview", { incidents: [{ id: "INC-LOW", priority: "low", status: "open" }] }, NOW), /fall within this report's scope/);
});

test("Daily SOC operations and Weekly incident summary anchor to the data's own recency, not wall-clock time (sample mode has frozen fixtures)", () => {
  const farFutureNow = new Date("2030-01-01T00:00:00Z");
  const events = [
    { id: "EVT-A", timestamp: "2026-07-16T13:36:32Z" },
    { id: "EVT-B", timestamp: "2026-07-16T14:32:09Z" },
  ];
  const dailyResult = createReportExport("Daily SOC operations", { events }, farFutureNow);
  assert.equal(dailyResult.recordCount, 2);

  const incidents = [
    { id: "INC-A", updated: "2026-07-16T13:00:00Z" },
    { id: "INC-B", updated: "2026-07-16T14:00:00Z" },
  ];
  const weeklyResult = createReportExport("Weekly incident summary", { incidents }, farFutureNow);
  assert.equal(weeklyResult.recordCount, 2);
});

test("previewReportRecordCount mirrors the exported count without throwing on missing or unknown data", () => {
  assert.equal(previewReportRecordCount("Daily SOC operations", {}), 0);
  assert.equal(previewReportRecordCount("unknown", { events: [{ id: "EVT-1" }] }), 0);
  const events = [{ id: "EVT-1", timestamp: "2026-10-25T10:00:00Z" }];
  assert.equal(previewReportRecordCount("Daily SOC operations", { events }, NOW), 1);
});

test("spreadsheet cells escape formulas even after whitespace and retain quoted text", () => {
  for (const input of ["=1+1", " +SUM(1)", "\t@SUM(1)", "\r-1+1"]) assert.ok(escapeCsvCell(input).startsWith('"\''));
  assert.equal(escapeCsvCell('A "quoted" note'), '"A ""quoted"" note"');
});

test("downloads attach and remove their link and revoke URLs after success or failure", () => {
  const previous = { document: globalThis.document, window: globalThis.window, create: URL.createObjectURL, revoke: URL.revokeObjectURL };
  let removed = 0, revoked = 0, clicked = 0, timer;
  const link = { click() { clicked += 1; }, remove() { removed += 1; } };
  globalThis.document = { createElement: () => link, body: { append() {} } };
  globalThis.window = { setTimeout(callback) { timer = callback; } };
  URL.createObjectURL = () => "blob:test"; URL.revokeObjectURL = () => { revoked += 1; };
  try {
    assert.equal(downloadCsvFile('"id"\n"1"', "report.csv"), "report.csv");
    assert.equal(link.download, "report.csv"); assert.equal(clicked, 1); assert.equal(removed, 1); assert.equal(revoked, 0);
    timer(); assert.equal(revoked, 1);
    link.click = () => { throw new Error("Download blocked"); };
    assert.throws(() => downloadCsvFile("csv", "report.csv"), /Download blocked/);
    assert.equal(revoked, 2); assert.equal(removed, 2);
  } finally { globalThis.document = previous.document; globalThis.window = previous.window; URL.createObjectURL = previous.create; URL.revokeObjectURL = previous.revoke; }
});
