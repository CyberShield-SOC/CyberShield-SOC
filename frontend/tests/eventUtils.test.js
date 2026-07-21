import test from "node:test";
import assert from "node:assert/strict";
import { File } from "node:buffer";
import {
  alertsToCsv,
  escapeCsvCell,
  eventsToCsv,
  filterEvents,
  formatTimestamp,
  incidentsToCsv,
  inspectLogFile,
  validateLogFile,
} from "../src/soc/utils/eventUtils.js";

const events = [
  {
    id: "EVT-1",
    timestamp: "2026-07-16T12:00:00Z",
    source: "auth.log",
    sourceIp: "203.0.113.88",
    user: "root",
    event: "Failed login",
    severity: "critical",
    status: "failed",
    risk: 96,
    rule: "R-101",
    message: "Repeated authentication failures",
  },
  {
    id: "EVT-2",
    timestamp: "2026-07-16T12:01:00Z",
    source: "firewall",
    sourceIp: "10.0.4.17",
    user: "system",
    event: "Connection allowed",
    severity: "info",
    status: "success",
    risk: 18,
    rule: "R-210",
    message: "Approved connection",
  },
];

test("filters normalized events across search and exact facets", () => {
  assert.deepEqual(filterEvents(events, { query: "203.0.113", severity: "critical", status: "failed", source: "" }).map((event) => event.id), ["EVT-1"]);
  assert.deepEqual(filterEvents(events, { query: "connection", severity: "", status: "success", source: "firewall" }).map((event) => event.id), ["EVT-2"]);
  assert.deepEqual(filterEvents(events, { query: "missing", severity: "", status: "", source: "" }), []);
});

test("escapes CSV content and neutralizes spreadsheet formulas", () => {
  assert.equal(escapeCsvCell("hello, world"), '"hello, world"');
  assert.equal(escapeCsvCell('quoted "value"'), '"quoted ""value"""');
  assert.equal(escapeCsvCell("=HYPERLINK(\"https://example.com\")"), '"\'=HYPERLINK(""https://example.com"")"');
  assert.match(eventsToCsv(events), /^"id","timestamp","source"/);
  assert.match(eventsToCsv(events), /"EVT-1"/);
});

test("exports incident history with formula-safe cells", () => {
  const csv = incidentsToCsv([{ id: "INC-1", title: "=unsafe", owner: "Analyst", priority: "high", status: "false positive", updated: "2026-07-17", completedAt: "2026-07-17", completedBy: "Yugal P.", summary: "Done" }]);
  assert.match(csv, /^"id","title","owner"/);
  assert.match(csv, /"'=unsafe"/);
  assert.match(csv, /"false positive"/);
  assert.match(csv, /"Yugal P\."/);
});

test("exports alerts with formula-safe cells", () => {
  const csv = alertsToCsv([{ id: "ALT-1", ruleId: "R-101", ruleName: "brute force login", severity: "high", status: "new", sourceIp: "203.0.113.4", user: "root", firstSeen: "2026-07-17T00:00:00Z", lastSeen: "2026-07-17T00:01:00Z", summary: "=unsafe" }]);
  assert.match(csv, /^"id","ruleId","ruleName"/);
  assert.match(csv, /"R-101"/);
  assert.match(csv, /"'=unsafe"/);
});

test("formats invalid backend timestamps as a stable fallback", () => {
  assert.equal(formatTimestamp("not-a-date"), "Unknown time");
  assert.notEqual(formatTimestamp("2026-07-16T12:00:00Z"), "Unknown time");
});

test("rejects unsupported, empty, and oversized log files before upload", () => {
  assert.throws(() => validateLogFile({ name: "events.exe", size: 12 }), /Choose a/);
  assert.throws(() => validateLogFile({ name: "events.log", size: 0 }), /empty/);
  assert.throws(
    () => validateLogFile({ name: "events.csv", size: 10 * 1024 * 1024 + 1 }, { maxBytes: 10 * 1024 * 1024 }),
    /10 MB or smaller/,
  );
  assert.equal(validateLogFile({ name: "EVENTS.CSV", size: 512 }, { maxBytes: 10 * 1024 * 1024 }), true);
  assert.equal(validateLogFile({ name: "events.json", size: 512 }), true);
  assert.equal(validateLogFile({ name: "events.JSONL", size: 512 }), true);
});

test("inspects supported file content and reports non-empty record counts", async () => {
  const csv = new File(["timestamp,event\n2026-07-17,login\n2026-07-17,logout\n"], "events.csv", { type: "text/csv" });
  const result = await inspectLogFile(csv);

  assert.deepEqual(result, { name: "events.csv", records: 3, size: csv.size });
});

test("rejects blank and unsupported file content in the local inspector", async () => {
  const blank = new File([" \n\t\n"], "empty.log", { type: "text/plain" });
  const text = new File(["event"], "events.txt", { type: "text/plain" });

  await assert.rejects(() => inspectLogFile(blank), /does not contain any log records/);
  await assert.rejects(() => inspectLogFile(text), /Choose a/);
});
