import { incidentMatchesAlert } from "./alertRecommendations.js";
import { isTerminalIncidentStatus } from "./incidentWorkflow.js";

const TERMINAL_ALERT_STATUSES = new Set(["contained", "resolved", "closed", "false positive"]);

export function isActiveAlert(alert) {
  return !TERMINAL_ALERT_STATUSES.has(String(alert?.status || "").toLowerCase());
}

export function isQuickResolvableAlert(alert, incidents = []) {
  if (!isActiveAlert(alert)) return false;
  const linkedIncident = incidents.find((incident) => incidentMatchesAlert(incident, alert));
  return !linkedIncident || !isTerminalIncidentStatus(linkedIncident.status);
}

export function filterAlertsForPicker(alerts, query) {
  const normalizedQuery = String(query || "").trim().toLowerCase();
  if (!normalizedQuery) return alerts;

  return alerts.filter((alert) => [
    alert.id,
    alert.title,
    alert.severity,
    alert.status,
    alert.sourceIp,
    alert.user,
    alert.ruleId,
    alert.ruleName,
  ].join(" ").toLowerCase().includes(normalizedQuery));
}

export function deriveWorkspaceCounts(alerts, incidents, notifications = []) {
  return {
    activeAlerts: alerts.filter(isActiveAlert).length,
    openIncidents: incidents.filter((incident) => !isTerminalIncidentStatus(incident?.status)).length,
    unreadNotifications: notifications.filter((notification) => !notification.read).length,
  };
}
