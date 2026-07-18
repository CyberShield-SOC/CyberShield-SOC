/**
 * Frontend catalog for the rules registered by backend DetectionEngine.
 * Keep these identifiers and thresholds aligned with backend/app/detection/rules.
 */
export const CURRENT_DETECTION_RULES = Object.freeze({
  "R-101": Object.freeze({
    id: "R-101",
    engineKey: "brute_force_login",
    name: "Brute-force login detection",
    description: "Detects concentrated failed login attempts from one source address.",
    technique: "T1110.001 · Password Guessing",
    severity: "high",
    version: "Built-in",
    status: "enabled",
    owner: "Detection Engineering",
    lastUpdated: "Current deployment",
    criteria: "5 failed login attempts from one source IP within 60 seconds",
    input: "FAILED login_attempt events with a source IP",
    groupBy: "Source IP",
    query: "status=FAILED event_type=login_attempt | window 60s by source_ip | count >= 5",
    response: "Block the source IP, reset affected credentials, and review successful logins from the same source.",
  }),
  "R-102": Object.freeze({
    id: "R-102",
    engineKey: "invalid_user_enumeration",
    name: "Invalid account enumeration",
    description: "Detects one source attempting several distinct account names during failed logins.",
    technique: "T1087 · Account Discovery",
    severity: "medium",
    version: "Built-in",
    status: "enabled",
    owner: "Identity Security",
    lastUpdated: "Current deployment",
    criteria: "3 distinct usernames from one source IP within 600 seconds",
    input: "FAILED login_attempt events with a source IP and username",
    groupBy: "Source IP",
    query: "status=FAILED event_type=login_attempt | window 600s by source_ip | distinct(username) >= 3",
    response: "Investigate and block the source IP, then review the attempted identities for targeted reconnaissance.",
  }),
  "R-103": Object.freeze({
    id: "R-103",
    engineKey: "sudo_failure",
    name: "Repeated sudo failure",
    description: "Detects repeated failed privilege-escalation attempts by the same user or source.",
    technique: "T1548 · Abuse Elevation Control Mechanism",
    severity: "medium",
    version: "Built-in",
    status: "enabled",
    owner: "Linux Security",
    lastUpdated: "Current deployment",
    criteria: "3 failed sudo attempts by one user or source within 300 seconds",
    input: "FAILED privilege_escalation events",
    groupBy: "Username, falling back to source IP",
    query: "status=FAILED event_type=privilege_escalation | window 300s by user or source_ip | count >= 3",
    response: "Review the account and host, enforce MFA for privileged access, and audit any successful sudo activity.",
  }),
});

export const CURRENT_DETECTION_RULE_IDS = Object.freeze(
  Object.keys(CURRENT_DETECTION_RULES),
);

export function summarizeRuleActivity(ruleId, alerts = []) {
  const safeAlerts = Array.isArray(alerts) ? alerts : [];
  const matches = safeAlerts.filter((alert) => alert?.ruleId === ruleId);
  const active = matches.filter((alert) => !["closed", "resolved"].includes(
    String(alert?.status || "").toLowerCase(),
  ));
  const timestamps = matches
    .map((alert) => new Date(alert?.createdAt || alert?.observedAt || "").getTime())
    .filter(Number.isFinite);

  return {
    active: active.length,
    latest: timestamps.length ? new Date(Math.max(...timestamps)).toISOString() : null,
    total: matches.length,
  };
}
