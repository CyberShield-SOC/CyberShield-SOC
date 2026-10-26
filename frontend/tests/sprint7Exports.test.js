import test from "node:test";
import assert from "node:assert/strict";
import { createReportExport, REPORT_EXPORTERS } from "../src/soc/utils/reportExport.js";
import { downloadCsvFile, escapeCsvCell } from "../src/soc/utils/eventUtils.js";

test("every report exports the selected loaded records with a dated CSV filename", () => {
  const data = { events: [{ id: "EVT-1" }], incidents: [{ id: "INC-1", resolutionReason: "Contained", resolutionNote: "Verified original source" }], alerts: [{ id: "ALT-1", risk: 30 }, { id: "ALT-2", risk: 96 }] };
  for (const name of Object.keys(REPORT_EXPORTERS)) {
    const result = createReportExport(name, data, new Date("2026-10-25T12:00:00Z"));
    assert.match(result.filename, /^cybershield-[a-z-]+-2026-10-25\.csv$/);
    assert.equal(result.recordCount, data[REPORT_EXPORTERS[name].key].length);
    assert.equal(result.csv.split("\n").length, result.recordCount + 1);
  }
  const report = createReportExport("Executive risk overview", data);
  assert.ok(report.csv.indexOf("ALT-2") < report.csv.indexOf("ALT-1"));
  assert.equal(data.alerts[0].id, "ALT-1");
  assert.match(createReportExport("Weekly incident summary", data).csv, /Contained/);
  assert.throws(() => createReportExport("unknown", data), /supported report/);
  assert.throws(() => createReportExport("Daily SOC operations", { events: [] }), /No events/);
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
