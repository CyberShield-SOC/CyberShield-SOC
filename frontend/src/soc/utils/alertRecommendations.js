import { incidentStatusLabel, isTerminalIncidentStatus } from "./incidentWorkflow.js";

const RESPONSE_PLAYBOOKS = Object.freeze({
  bruteForce: [
    "Block the source IP at the perimeter while validation is in progress.",
    "Reset the affected account password and revoke active sessions.",
    "Review successful authentications from the same source and targeted identities.",
    "Confirm MFA and privileged-login restrictions are enforced.",
  ],
  invalidUser: [
    "Investigate the source IP and block it when the activity is not authorized.",
    "Review the attempted account names for targeted identity enumeration.",
    "Check the source for related authentication or reconnaissance alerts.",
  ],
  sudoFailure: [
    "Review the affected account, host, and preceding login activity.",
    "Enable or enforce MFA for privileged access.",
    "Audit successful sudo activity and rotate credentials if compromise is suspected.",
  ],
  successfulLogin: [
    "Lock the affected account and revoke active sessions.",
    "Investigate the source host and destination system for compromise.",
    "Reset credentials and validate MFA enrollment before restoring access.",
  ],
  powershell: [
    "Isolate the affected host if the execution is not approved.",
    "Collect the process tree, command line, script content, and file hashes.",
    "Block confirmed malicious indicators and hunt for related execution.",
  ],
  missingMfa: [
    "Revoke the privileged cloud session and restrict the affected account.",
    "Enforce MFA before allowing another privileged sign-in.",
    "Review cloud audit activity for changes made during the session.",
  ],
  threatIntel: [
    "Block the matched indicator at the appropriate network control.",
    "Review related inbound and outbound traffic for successful exploitation.",
    "Validate exposure of the targeted asset and escalate confirmed compromise.",
  ],
  malware: [
    "Isolate the endpoint and quarantine the detected artifact.",
    "Collect endpoint indicators and investigate the process ancestry.",
    "Hunt for the same indicators and reset credentials if theft is possible.",
  ],
  domainReputation: [
    "Block the domain when it is not required for approved business activity.",
    "Identify clients that resolved or contacted the domain.",
    "Inspect those systems for payload delivery and recurring DNS activity.",
  ],
  exfiltration: [
    "Contain the affected host or identity and block the destination.",
    "Preserve proxy, endpoint, and identity evidence for the transfer window.",
    "Determine what data left the environment and notify the response lead.",
  ],
});

function alertSearchText(alert) {
  return [alert?.ruleId, alert?.ruleName, alert?.title, alert?.summary, alert?.reason]
    .join(" ")
    .toLowerCase();
}

export function getAlertRecommendations(alert) {
  const text = alertSearchText(alert);
  if (!text.trim()) return [];

  if (text.includes("r-101") || text.includes("brute_force") || text.includes("brute-force") || text.includes("password spray")) return RESPONSE_PLAYBOOKS.bruteForce;
  if (text.includes("r-102") || text.includes("invalid_user") || text.includes("invalid user") || text.includes("enumeration")) return RESPONSE_PLAYBOOKS.invalidUser;
  if (text.includes("r-103") || text.includes("sudo_failure") || text.includes("sudo failure")) return RESPONSE_PLAYBOOKS.sudoFailure;
  if (text.includes("successful login") || text.includes("login success") || text.includes("accepted password")) return RESPONSE_PLAYBOOKS.successfulLogin;
  if (text.includes("r-411") || text.includes("powershell") || text.includes("script execution")) return RESPONSE_PLAYBOOKS.powershell;
  if (text.includes("r-620") || text.includes("without mfa") || text.includes("mfa policy")) return RESPONSE_PLAYBOOKS.missingMfa;
  if (text.includes("r-205") || text.includes("threat intelligence") || text.includes("malicious ip")) return RESPONSE_PLAYBOOKS.threatIntel;
  if (text.includes("r-430") || text.includes("malware")) return RESPONSE_PLAYBOOKS.malware;
  if (text.includes("r-507") || text.includes("domain reputation") || text.includes("newly registered domain")) return RESPONSE_PLAYBOOKS.domainReputation;
  if (text.includes("r-710") || text.includes("exfiltration") || text.includes("outbound transfer")) return RESPONSE_PLAYBOOKS.exfiltration;
  return [];
}

export function incidentMatchesAlert(incident, alert) {
  if (!incident || !alert) return false;
  if (incident.sourceAlertId != null && alert.sourceAlertId != null) {
    return String(incident.sourceAlertId) === String(alert.sourceAlertId);
  }
  const incidentEventIds = new Set(incident.eventIds || []);
  return (alert.evidenceIds || []).some((eventId) => incidentEventIds.has(eventId));
}

/**
 * Keeps the incident call to action truthful: linked records expose their
 * current state, while unlinked high-risk alerts use the stronger promotion
 * language. Lower-risk records remain available for analyst-created cases.
 */
export function getIncidentActionLabel(linkedIncident, alertSeverity) {
  if (!linkedIncident) {
    return ["critical", "high"].includes(String(alertSeverity || "").toLowerCase())
      ? "Promote to incident"
      : "Create incident";
  }

  const verb = isTerminalIncidentStatus(linkedIncident.status) ? "View" : "Go to";
  return `${verb} incident · ${incidentStatusLabel(linkedIncident.status)}`;
}
