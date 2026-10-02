import { isTerminalIncidentStatus } from "./incidentWorkflow.js";

export function normalizedEvidenceRows(event) {
  if (!event) return [];
  return [
    ["Timestamp", event.timestamp],
    ["Source", event.source],
    ["Source IP", event.sourceIp],
    ["User", event.user],
    ["Event", event.event],
    ["Severity", event.severity],
    ["Status", event.status],
    ["Rule", event.rule],
  ].filter(([, value]) => value !== undefined && value !== null && value !== "");
}

export function rawEvidenceRows(alert, event) {
  const raw = alert?.evidence && typeof alert.evidence === "object" && !Array.isArray(alert.evidence)
    ? alert.evidence
    : {};
  const rows = Object.entries(raw).map(([key, value]) => [key, value]);
  if (event?.message && !rows.some(([key]) => key === "raw_message")) rows.push(["raw_message", event.message]);
  return rows;
}

export function formatEvidenceValue(value) {
  if (Array.isArray(value)) return value.join(", ");
  if (value && typeof value === "object") return JSON.stringify(value);
  return String(value ?? "Unknown");
}

export function relatedAlertsForAlert(alert, alerts, events = []) {
  if (!alert) return [];
  const selectedTime = Date.parse(alert.observedAt || alert.createdAt || alert.firstSeen || "");
  const selectedEvidence = new Set(alert.evidenceIds || []);
  return alerts
    .filter((candidate) => candidate.id !== alert.id)
    .map((candidate) => {
      const candidateTime = Date.parse(candidate.observedAt || candidate.createdAt || candidate.firstSeen || "");
      const sharedEvidence = (candidate.evidenceIds || []).filter((id) => selectedEvidence.has(id));
      const sharedFields = [
        candidate.sourceIp && candidate.sourceIp === alert.sourceIp ? "source IP" : "",
        candidate.user && candidate.user === alert.user ? "user" : "",
        candidate.ruleId && candidate.ruleId === alert.ruleId ? "rule" : "",
        sharedEvidence.length ? "evidence" : "",
      ].filter(Boolean);
      const withinWindow = Number.isFinite(selectedTime) && Number.isFinite(candidateTime)
        ? Math.abs(candidateTime - selectedTime) <= 30 * 60 * 1000
        : true;
      if (!sharedFields.length || !withinWindow) return null;
      const linkedEvents = events.filter((event) => (candidate.evidenceIds || []).includes(event.id));
      return {
        alert: candidate,
        reason: `Shared ${sharedFields.join(", ")}`,
        groupingEntity: candidate.sourceIp === alert.sourceIp ? alert.sourceIp : candidate.user || candidate.ruleId,
        timeWindow: "30 minutes",
        linkedEvents,
      };
    })
    .filter(Boolean)
    .sort((a, b) => Date.parse(b.alert.observedAt || b.alert.createdAt || "") - Date.parse(a.alert.observedAt || a.alert.createdAt || ""));
}

export function investigationHistoryForIncident(incident, notes = []) {
  if (!incident) return [];
  const base = [
    {
      id: `${incident.id}-created`,
      at: incident.createdAt || incident.updated,
      title: "Incident record available",
      detail: incident.sourceAlertId ? `Linked to alert ${incident.sourceAlertId}` : "Created from SOC queue",
    },
    {
      id: `${incident.id}-status`,
      at: incident.updated,
      title: `Status: ${incident.status}`,
      detail: incident.owner || "Unassigned",
    },
  ];
  if (isTerminalIncidentStatus(incident.status)) {
    base.push({
      id: `${incident.id}-closed`,
      at: incident.completedAt || incident.updated,
      title: incident.status === "false positive" ? "Marked false positive" : "Resolved",
      detail: incident.completedBy ? `By ${incident.completedBy}` : "Completed investigation",
    });
  }
  const noteRows = notes
    .filter((note) => note.linkedType === "incident" && note.linkedId === incident.id && !note.archived)
    .map((note) => ({
      id: note.id,
      at: note.updatedAt || note.createdAt,
      title: note.title,
      detail: note.author,
    }));
  return [...base, ...noteRows].sort((a, b) => Date.parse(b.at || "") - Date.parse(a.at || ""));
}
