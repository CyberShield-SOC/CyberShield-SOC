import test from "node:test";
import assert from "node:assert/strict";
import {
  buildSeverityBuckets,
  buildTimeBuckets,
  calculateSecurityGrade,
  filterRecordsByTimeRange,
  summarizeIpActivity,
} from "../src/soc/utils/timeRange.js";

const now = Date.parse("2026-07-17T12:00:00Z");

test("filters records and buckets ingestion by the selected range", () => {
  const records = [
    { ingestedAt: "2026-07-17T11:30:00Z" },
    { ingestedAt: "2026-07-16T13:00:00Z" },
    { ingestedAt: "invalid" },
  ];
  assert.equal(filterRecordsByTimeRange(records, "1h", "ingestedAt", now).length, 2);
  const series = buildTimeBuckets(records, "24h", "ingestedAt", now);
  assert.equal(series.values.reduce((sum, value) => sum + value, 0), 2);
  assert.equal(series.values.length, 12);
  assert.equal(filterRecordsByTimeRange(records, "all", "ingestedAt", now).length, 3);
  const allSeries = buildTimeBuckets(records, "all", "ingestedAt", now);
  assert.equal(allSeries.values.reduce((sum, value) => sum + value, 0), 2);
  assert.equal(allSeries.values.length, 12);
});

test("uses calendar dates for the seven-day chart timeline", () => {
  const series = buildTimeBuckets([], "7d", "ingestedAt", now);
  assert.match(series.labels[0], /[A-Z][a-z]{2} \d{1,2}/);
  assert.equal(series.labels.length, 7);
});

test("buckets large all-time imports without spreading timestamp arrays", () => {
  const records = Array.from({ length: 150_000 }, (_, index) => ({
    timestamp: new Date(now - index * 1_000).toISOString(),
  }));
  const result = buildTimeBuckets(records, "all", "timestamp", now);
  assert.equal(result.values.reduce((sum, value) => sum + value, 0), records.length);
  assert.equal(result.end, now);
});

test("includes the calendar date and time in hourly chart labels", () => {
  const series = buildTimeBuckets([], "24h", "ingestedAt", now);
  assert.match(series.labels[0], /[A-Z][a-z]{2} \d{1,2}\n/);
  assert.match(series.labels[0], /(AM|PM)/);
  assert.equal(series.labels.length, 12);
});

test("builds alert severity buckets without accepting unknown severities", () => {
  const buckets = buildSeverityBuckets([
    { createdAt: "2026-07-17T11:00:00Z", severity: "critical" },
    { createdAt: "2026-07-17T11:05:00Z", severity: " High " },
    { createdAt: "2026-07-17T11:10:00Z", severity: "unknown" },
  ], "24h", now);
  assert.equal(buckets.reduce((sum, bucket) => sum + bucket.critical, 0), 1);
  assert.equal(buckets.reduce((sum, bucket) => sum + bucket.high, 0), 1);
  assert.equal(buildSeverityBuckets(null, "24h", now).length, 12);
});

test("derives a bounded grade and unique versus recurring IP counts", () => {
  assert.deepEqual(summarizeIpActivity([
    { sourceIp: "203.0.113.1" },
    { sourceIp: "203.0.113.1" },
    { sourceIp: "198.51.100.2" },
    { sourceIp: "Unknown" },
  ]), { unique: 2, recurring: 1 });
  const grade = calculateSecurityGrade({
    alerts: [{ severity: "critical", status: "new" }],
    incidents: [{ status: "new" }],
    events: [{ status: "failed" }],
  });
  assert.equal(grade.grade, "C");
  assert.equal(grade.score, 78);
});
