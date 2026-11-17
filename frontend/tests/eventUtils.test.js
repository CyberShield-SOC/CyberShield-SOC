import test from "node:test";
import assert from "node:assert/strict";
import { File } from "node:buffer";
import {
  filterEvents,
  formatTimestamp,
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
  assert.equal(validateLogFile({ name: "events.txt", size: 512 }), true);
  assert.equal(validateLogFile({ name: "EVENTS.TXT", size: 512 }), true);
});

test("inspects supported file content and reports non-empty record counts", async () => {
  const csv = new File(["timestamp,event\n2026-07-17,login\n2026-07-17,logout\n"], "events.csv", { type: "text/csv" });
  const result = await inspectLogFile(csv);

  assert.deepEqual(result, { name: "events.csv", records: 3, size: csv.size });
});

test("rejects blank and unsupported file content in the local inspector", async () => {
  const blank = new File([" \n\t\n"], "empty.log", { type: "text/plain" });
  const unsupported = new File(["event"], "events.pdf", { type: "application/pdf" });

  await assert.rejects(() => inspectLogFile(blank), /does not contain any log records/);
  await assert.rejects(() => inspectLogFile(unsupported), /Choose a/);
});

test("inspects .txt files the same way as other supported log formats", async () => {
  const txt = new File(["event one\nevent two\n"], "events.txt", { type: "text/plain" });
  const result = await inspectLogFile(txt);

  assert.deepEqual(result, { name: "events.txt", records: 2, size: txt.size });
});
