import { alertsToCsv, detectionCoverageToCsv, eventsToCsv, incidentsToCsv } from "./eventUtils.js";
import { isTerminalIncidentStatus } from "./incidentWorkflow.js";
import { filterRecordsByTimeRange } from "./timeRange.js";

const PRIORITY_RANK = Object.freeze({ critical: 4, high: 3, medium: 2, low: 1 });
const SEVERITY_KEYS = Object.freeze(["critical", "high", "medium", "low"]);

function timeOf(value) {
  const timestamp = new Date(value).getTime();
  return Number.isFinite(timestamp) ? timestamp : null;
}

// The frontend only ever has a point-in-time snapshot (the latest loaded
// upload, or whatever's currently loaded) rather than a live feed, and
// sample-mode fixtures are frozen at a fixed past date. Anchoring the
// "last N" window to the newest timestamp actually present in the data —
// falling back to wall-clock time only when every record is undated —
// keeps a recent-but-not-literally-live snapshot from reading as empty.
function latestTimestamp(records, field, fallbackMs) {
  const times = records.map((record) => timeOf(record?.[field])).filter((value) => value !== null);
  return times.length ? Math.max(...times) : fallbackMs;
}

/** One row per detection rule: hit counts by severity, MITRE technique, first/last seen. */
export function summarizeRuleCoverage(alerts) {
  const groups = new Map();
  alerts.forEach((alert) => {
    const ruleId = alert.ruleId || "";
    const ruleName = alert.ruleName || ruleId || "Unknown rule";
    const key = ruleId || ruleName;
    if (!groups.has(key)) {
      groups.set(key, { ruleId, ruleName, mitreTechnique: alert.mitreTechnique || "", count: 0, critical: 0, high: 0, medium: 0, low: 0, firstSeen: null, lastSeen: null });
    }
    const group = groups.get(key);
    group.count += 1;
    const severity = String(alert.severity || "").toLowerCase();
    if (SEVERITY_KEYS.includes(severity)) group[severity] += 1;
    if (!group.mitreTechnique && alert.mitreTechnique) group.mitreTechnique = alert.mitreTechnique;
    const first = timeOf(alert.firstSeen || alert.createdAt);
    const last = timeOf(alert.lastSeen || alert.firstSeen || alert.createdAt);
    if (first !== null && (group.firstSeen === null || first < group.firstSeen)) group.firstSeen = first;
    if (last !== null && (group.lastSeen === null || last > group.lastSeen)) group.lastSeen = last;
  });
  return [...groups.values()]
    .sort((a, b) => b.count - a.count)
    .map((group) => ({
      ...group,
      firstSeen: group.firstSeen !== null ? new Date(group.firstSeen).toISOString() : "",
      lastSeen: group.lastSeen !== null ? new Date(group.lastSeen).toISOString() : "",
    }));
}

/** Open, highest-priority incidents, most recently updated first. */
function selectOpenHighRiskIncidents(incidents) {
  return incidents
    .filter((incident) => !isTerminalIncidentStatus(incident.status) && (PRIORITY_RANK[incident.priority] || 0) >= PRIORITY_RANK.high)
    .sort((a, b) => (PRIORITY_RANK[b.priority] || 0) - (PRIORITY_RANK[a.priority] || 0) || (timeOf(b.updated) || 0) - (timeOf(a.updated) || 0));
}

export const REPORT_EXPORTERS = Object.freeze({
  "Daily SOC operations": {
    key: "events",
    unit: "events",
    filename: "daily-soc-operations",
    scope: "Events from the last 24 hours",
    description: "Normalized events from the last 24 hours of the latest loaded upload.",
    select: (events, nowMs) => filterRecordsByTimeRange(events, "24h", "timestamp", latestTimestamp(events, "timestamp", nowMs)),
    csv: eventsToCsv,
  },
  "Weekly incident summary": {
    key: "incidents",
    unit: "incidents",
    filename: "incident-summary",
    scope: "Incidents updated in the last 7 days",
    description: "Incidents updated in the last 7 days, with assignment, status and resolution details.",
    select: (incidents, nowMs) => filterRecordsByTimeRange(incidents, "7d", "updated", latestTimestamp(incidents, "updated", nowMs)),
    csv: incidentsToCsv,
  },
  "Detection coverage": {
    key: "alerts",
    unit: "rules",
    filename: "detection-coverage",
    scope: "One row per detection rule, aggregated from loaded alerts",
    description: "Per-rule alert coverage: hit counts by severity, MITRE technique, and first/last seen.",
    select: (alerts) => summarizeRuleCoverage(alerts),
    csv: detectionCoverageToCsv,
  },
  "Executive risk overview": {
    key: "incidents",
    unit: "incidents",
    filename: "executive-risk-overview",
    scope: "Open High/Critical incidents only",
    description: "Open High and Critical incidents, highest priority and most recently updated first.",
    select: (incidents) => selectOpenHighRiskIncidents(incidents),
    csv: incidentsToCsv,
  },
});

/** Record count a report would export right now, without throwing — safe to call from render. */
export function previewReportRecordCount(name, data, now = new Date()) {
  const definition = REPORT_EXPORTERS[name];
  if (!definition) return 0;
  const source = data[definition.key];
  if (!Array.isArray(source) || !source.length) return 0;
  return definition.select(source, now.getTime()).length;
}

export function createReportExport(name, data, now = new Date()) {
  const definition = REPORT_EXPORTERS[name];
  if (!definition) throw new Error("Choose a supported report.");
  const source = data[definition.key];
  if (!Array.isArray(source) || !source.length) throw new Error(`No ${definition.key} are available to export.`);
  const records = definition.select(source, now.getTime());
  if (!records.length) throw new Error(`No ${definition.key} fall within this report's scope.`);
  return { csv: definition.csv(records), filename: `cybershield-${definition.filename}-${now.toISOString().slice(0, 10)}.csv`, recordCount: records.length };
}
