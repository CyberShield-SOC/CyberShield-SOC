/**
 * Canonical incident lifecycle shared by every SOC workflow. Keeping this in
 * one module prevents pages, badges, API adapters, and tests from drifting.
 */
export const INCIDENT_STATUSES = Object.freeze([
  "open",
  "investigating",
  "resolved",
  "false positive",
]);

const TERMINAL_STATUSES = new Set(["resolved", "false positive"]);

export function normalizeIncidentStatus(status) {
  return String(status || "").trim().toLowerCase();
}

export function isTerminalIncidentStatus(status) {
  return TERMINAL_STATUSES.has(normalizeIncidentStatus(status));
}

export function incidentTerminalAction(status) {
  const normalized = normalizeIncidentStatus(status);
  if (normalized === "resolved") {
    return {
      title: "Resolve this incident?",
      description: "This will remove the incident from the active queue and add the completed investigation to incident history.",
      confirmLabel: "Resolve incident",
      successMessage: "resolved and added to incident history",
    };
  }
  if (normalized === "false positive") {
    return {
      title: "Mark as false positive?",
      description: "This will close the active investigation as a false positive and add the decision to incident history.",
      confirmLabel: "Mark false positive",
      successMessage: "marked as a false positive and added to incident history",
    };
  }
  return null;
}

export function incidentStatusLabel(status) {
  const normalized = normalizeIncidentStatus(status) || "open";
  return normalized.replace(/\b\w/g, (character) => character.toUpperCase());
}

export function nextIncidentWorkflowAction(status) {
  const normalized = normalizeIncidentStatus(status);
  if (normalized === "open") return ["investigating", "Start investigation"];
  if (normalized === "investigating") return ["resolved", "Resolve incident"];
  return null;
}
