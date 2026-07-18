import { isTerminalIncidentStatus } from "./incidentWorkflow.js";

const RANGE_CONFIG = Object.freeze({
  "1h": { durationMs: 60 * 60 * 1000, buckets: 12 },
  "24h": { durationMs: 24 * 60 * 60 * 1000, buckets: 12 },
  "7d": { durationMs: 7 * 24 * 60 * 60 * 1000, buckets: 7 },
  "30d": { durationMs: 30 * 24 * 60 * 60 * 1000, buckets: 10 },
  all: { durationMs: null, buckets: 12 },
});

export const TIME_RANGE_LABELS = Object.freeze({
  "1h": "Last hour",
  "24h": "Last 24 hours",
  "7d": "Last 7 days",
  "30d": "Last 30 days",
  all: "All available",
});

export function normalizeTimeRange(value) {
  return RANGE_CONFIG[value] ? value : "24h";
}

export function recordTimestamp(record, fields) {
  const candidates = Array.isArray(fields) ? fields : [fields];
  for (const field of candidates) {
    const timestamp = new Date(record?.[field]).getTime();
    if (Number.isFinite(timestamp)) return timestamp;
  }
  return null;
}

export function filterRecordsByTimeRange(records, range, fields, now = Date.now()) {
  const normalizedRange = normalizeTimeRange(range);
  if (normalizedRange === "all") return [...records];
  const { durationMs } = RANGE_CONFIG[normalizedRange];
  const start = now - durationMs;
  return records.filter((record) => {
    const timestamp = recordTimestamp(record, fields);
    // Keep legacy/mock records with display-only dates visible in queue views.
    return timestamp === null || (timestamp >= start && timestamp <= now);
  });
}

function labelForBucket(timestamp, range, durationMs) {
  const date = new Date(timestamp);
  const dateLabel = new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric" }).format(date);
  if (range === "1h") {
    const timeLabel = new Intl.DateTimeFormat(undefined, { hour: "numeric", minute: "2-digit" }).format(date);
    return `${dateLabel}\n${timeLabel}`;
  }
  if (range === "24h") {
    const timeLabel = new Intl.DateTimeFormat(undefined, { hour: "numeric" }).format(date);
    return `${dateLabel}\n${timeLabel}`;
  }
  if (range === "7d") {
    return dateLabel;
  }
  if (range === "all" && durationMs <= 24 * 60 * 60 * 1000) {
    const timeLabel = new Intl.DateTimeFormat(undefined, { hour: "numeric", minute: "2-digit" }).format(date);
    return `${dateLabel}\n${timeLabel}`;
  }
  return dateLabel;
}

export function buildTimeBuckets(records, range, fields, now = Date.now()) {
  const normalizedRange = normalizeTimeRange(range);
  const { buckets, durationMs: configuredDuration } = RANGE_CONFIG[normalizedRange];
  const timestamps = records
    .map((record) => recordTimestamp(record, fields))
    .filter((timestamp) => timestamp !== null);
  let end = now;
  let start = configuredDuration === null
    ? timestamps.reduce((earliest, timestamp) => Math.min(earliest, timestamp), Infinity)
    : now - configuredDuration;
  if (configuredDuration === null) {
    end = timestamps.reduce((latest, timestamp) => Math.max(latest, timestamp), -Infinity);
    if (!timestamps.length) end = now;
    if (!timestamps.length || start === end) start = end - 60 * 60 * 1000;
  }
  const durationMs = Math.max(end - start, 1);
  const bucketMs = durationMs / buckets;
  const values = Array(buckets).fill(0);

  records.forEach((record) => {
    const timestamp = recordTimestamp(record, fields);
    if (timestamp === null || timestamp < start || timestamp > end) return;
    const index = Math.min(Math.floor((timestamp - start) / bucketMs), buckets - 1);
    values[index] += 1;
  });

  return {
    values,
    labels: values.map((_, index) => labelForBucket(start + (index + 1) * bucketMs, normalizedRange, durationMs)),
    start,
    end,
    bucketMs,
  };
}

export function buildSeverityBuckets(alerts, range, now = Date.now()) {
  const safeAlerts = Array.isArray(alerts) ? alerts : [];
  const base = buildTimeBuckets(safeAlerts, range, "createdAt", now);
  const bucketMs = base.bucketMs;
  const series = base.labels.map((label) => ({ label, low: 0, medium: 0, high: 0, critical: 0 }));

  safeAlerts.forEach((alert) => {
    const timestamp = recordTimestamp(alert, "createdAt");
    if (timestamp === null || timestamp < base.start || timestamp > base.end) return;
    const index = Math.min(Math.floor((timestamp - base.start) / bucketMs), series.length - 1);
    const severity = String(alert?.severity || "").trim().toLowerCase();
    if (Object.hasOwn(series[index], severity)) series[index][severity] += 1;
  });
  return series;
}

export function calculateSecurityGrade({ alerts, incidents, events }) {
  const activeAlerts = alerts.filter((alert) => !["contained", "resolved", "closed"].includes(alert.status));
  const openIncidents = incidents.filter((incident) => !isTerminalIncidentStatus(incident.status));
  const penalty = (
    activeAlerts.filter((alert) => alert.severity === "critical").length * 12
    + activeAlerts.filter((alert) => alert.severity === "high").length * 5
    + openIncidents.length * 8
    + Math.min(events.filter((event) => event.status === "failed").length, 10) * 2
  );
  const score = Math.max(0, Math.min(100, 100 - penalty));
  const grade = score >= 90 ? "A" : score >= 80 ? "B" : score >= 70 ? "C" : score >= 60 ? "D" : "F";
  const tone = score >= 80 ? "success" : score >= 60 ? "warning" : "critical";
  return { grade, score, tone };
}

export function summarizeIpActivity(events) {
  const counts = new Map();
  events.forEach((event) => {
    const ip = String(event.sourceIp || "").trim();
    if (!ip || ip.toLowerCase() === "unknown") return;
    counts.set(ip, (counts.get(ip) || 0) + 1);
  });
  return {
    unique: counts.size,
    recurring: [...counts.values()].filter((count) => count > 1).length,
  };
}
