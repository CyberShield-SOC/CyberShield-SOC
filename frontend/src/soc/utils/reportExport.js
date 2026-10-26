import { alertsToCsv, eventsToCsv, incidentsToCsv } from "./eventUtils.js";

export const REPORT_EXPORTERS = Object.freeze({
  "Daily SOC operations": { key: "events", description: "Normalized events from the latest loaded upload.", csv: eventsToCsv, filename: "daily-soc-operations" },
  "Weekly incident summary": { key: "incidents", description: "Loaded incidents with assignment, status and resolution details.", csv: incidentsToCsv, filename: "incident-summary" },
  "Detection coverage": { key: "alerts", description: "Loaded rule-based and ML alerts with their detection identifiers.", csv: alertsToCsv, filename: "detection-coverage" },
  "Executive risk overview": { key: "alerts", description: "Loaded alerts ordered by severity, highest first.", csv: alertsToCsv, filename: "executive-risk-overview", sort: true },
});

export function createReportExport(name, data, now = new Date()) {
  const definition = REPORT_EXPORTERS[name];
  if (!definition) throw new Error("Choose a supported report.");
  const source = data[definition.key];
  if (!Array.isArray(source) || !source.length) throw new Error(`No ${definition.key} are available to export.`);
  const records = definition.sort ? [...source].sort((a, b) => (Number(b.risk) || 0) - (Number(a.risk) || 0)) : source;
  return { csv: definition.csv(records), filename: `cybershield-${definition.filename}-${now.toISOString().slice(0, 10)}.csv`, recordCount: records.length };
}
