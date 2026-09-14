import { EXTENDED_DETECTION_RULES } from "./extendedDetectionRules.js";

/**
 * Frontend catalog for the rules registered by backend DetectionEngine.
 * Keep these identifiers and thresholds aligned with backend/app/detection/rules.
 * The 28 built-ins are the eight core rules below (R-101..R-108) plus the
 * Group A/B/C rules in extendedDetectionRules.js (R-A01..R-C06). Their IDs
 * deliberately don't use the numeric R-### form, which the custom Rule
 * Builder allocates from R-109 upward.
 */
const CORE_RULE_EXTRAS = Object.freeze({
  "R-101": { group: "Core", logSource: "Any authentication log", defaults: { threshold: 5, window_seconds: 60 } },
  "R-102": { group: "Core", logSource: "Any authentication log", defaults: { threshold: 3, window_seconds: 600 } },
  "R-103": { group: "Core", logSource: "Auth/syslog (sudo events)", defaults: { threshold: 3, window_seconds: 300 } },
  "R-104": { group: "Core", logSource: "Any authentication log", defaults: { threshold: 5, window_seconds: 600 } },
  "R-105": { group: "Core", logSource: "Any authentication log", defaults: { fail_threshold: 5, window_seconds: 60, success_window_seconds: 120 } },
  "R-106": { group: "Core", logSource: "Firewall/IDS logs or flow exports", defaults: { threshold: 10, window_seconds: 60 } },
  "R-107": { group: "Core", logSource: "Any authentication log", defaults: { threshold: 3, window_seconds: 300 } },
  "R-108": { group: "Core", logSource: "Auth/syslog (sudo events)", defaults: { window_seconds: 120 } },
});

const CORE_DETECTION_RULES = Object.freeze({
  "R-101": Object.freeze({
    id: "R-101",
    engineKey: "brute_force_login",
    category: "generic_detection",
    executable: true,
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
    category: "generic_detection",
    executable: true,
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
    category: "generic_detection",
    executable: true,
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
  "R-104": Object.freeze({
    id: "R-104",
    engineKey: "password_spraying",
    category: "generic_detection",
    executable: true,
    name: "Password spraying detection",
    description: "Detects one account receiving failed logins from many distinct source IPs, staying under per-IP brute-force thresholds.",
    technique: "T1110.003 · Password Spraying",
    severity: "high",
    version: "Built-in",
    status: "enabled",
    owner: "Detection Engineering",
    lastUpdated: "Current deployment",
    criteria: "5 distinct source IPs failing to authenticate against one username within 600 seconds",
    input: "FAILED login_attempt events with a source IP and username",
    groupBy: "Username",
    query: "status=FAILED event_type=login_attempt | window 600s by username | distinct(source_ip) >= 5",
    response: "Lock or force a password reset on the targeted account, block the offending source IPs, and confirm MFA is enforced.",
  }),
  "R-105": Object.freeze({
    id: "R-105",
    engineKey: "credential_stuffing_success",
    category: "generic_detection",
    executable: true,
    name: "Credential stuffing success",
    description: "Detects a successful login from a source IP immediately after a burst of failed logins from that same IP — a likely account takeover.",
    technique: "T1110 · Brute Force + T1078 · Valid Accounts",
    severity: "high",
    version: "Built-in",
    status: "enabled",
    owner: "Detection Engineering",
    lastUpdated: "Current deployment",
    criteria: "5 failed login attempts from one source IP within 60 seconds, followed by a successful login from that IP within 120 seconds",
    input: "FAILED and SUCCESS login_attempt events with a source IP",
    groupBy: "Source IP",
    query: "status=FAILED event_type=login_attempt | window 60s by source_ip | count >= 5 | followed_by status=SUCCESS within 120s",
    response: "Treat the account as compromised: force a password reset, revoke active sessions, and review activity performed after the successful login.",
  }),
  "R-106": Object.freeze({
    id: "R-106",
    engineKey: "port_scan",
    category: "generic_detection",
    executable: true,
    name: "Port scan detection",
    description: "Detects a burst of port-scan events from one source IP, indicating network service discovery.",
    technique: "T1046 · Network Service Discovery",
    severity: "medium",
    version: "Built-in",
    status: "enabled",
    owner: "Network Security",
    lastUpdated: "Current deployment",
    criteria: "10 scan events from one source IP within 60 seconds, or 10 distinct ports probed on one host within 60 seconds",
    input: "port_scan events with a source IP",
    groupBy: "Source IP",
    query: "event_type=port_scan | window 60s by source_ip | count >= 10",
    response: "Block the source IP at the perimeter and review which services or ports it probed for follow-on exploitation attempts.",
  }),
  "R-107": Object.freeze({
    id: "R-107",
    engineKey: "multi_ip_successful_login",
    category: "generic_detection",
    executable: true,
    name: "Multi-IP successful login",
    description: "Detects one account with successful logins from several distinct source IPs in a short window, a common sign of shared or compromised credentials.",
    technique: "T1078 · Valid Accounts",
    severity: "medium",
    version: "Built-in",
    status: "enabled",
    owner: "Identity Security",
    lastUpdated: "Current deployment",
    criteria: "3 distinct source IPs successfully authenticate as one username within 300 seconds",
    input: "SUCCESS login_attempt events with a source IP and username",
    groupBy: "Username",
    query: "status=SUCCESS event_type=login_attempt | window 300s by username | distinct(source_ip) >= 3",
    response: "Confirm the access with the account owner, force a password reset if unrecognized, and revoke sessions from unexpected source IPs.",
  }),
  "R-108": Object.freeze({
    id: "R-108",
    engineKey: "sudo_after_login",
    category: "generic_detection",
    executable: true,
    name: "Sudo immediately after login",
    description: "Detects a successful login followed quickly by successful privilege escalation for the same account, a common lateral-movement or account-takeover pattern.",
    technique: "T1078 · Valid Accounts + T1548 · Abuse Elevation Control Mechanism",
    severity: "medium",
    version: "Built-in",
    status: "enabled",
    owner: "Linux Security",
    lastUpdated: "Current deployment",
    criteria: "A successful privilege escalation within 120 seconds of a successful login for the same account",
    input: "SUCCESS login_attempt and privilege_escalation events with a username",
    groupBy: "Username",
    query: "status=SUCCESS event_type=login_attempt | followed_by status=SUCCESS event_type=privilege_escalation within 120s by username",
    response: "Confirm the escalation was authorized, review commands run after it, and rotate the account's credentials if it was not.",
  }),
});

export const CURRENT_DETECTION_RULES = Object.freeze({
  ...Object.fromEntries(Object.entries(CORE_DETECTION_RULES).map(([id, rule]) => [
    id,
    Object.freeze({ ...rule, ...CORE_RULE_EXTRAS[id] }),
  ])),
  ...EXTENDED_DETECTION_RULES,
});

/** engine key (backend rule name) -> catalog ID, e.g. "log_tampering" -> "R-A05". */
export const RULE_ID_BY_ENGINE_KEY = Object.freeze(Object.fromEntries(
  Object.values(CURRENT_DETECTION_RULES).map((rule) => [rule.engineKey, rule.id]),
));

export const CURRENT_DETECTION_RULE_IDS = Object.freeze(
  Object.keys(CURRENT_DETECTION_RULES),
);

/**
 * Presentation-only examples for category discovery and future authoring.
 * These definitions deliberately have no engine key and are never registered
 * with DetectionEngine.
 */
export const SAMPLE_DETECTION_RULES = Object.freeze({
  "R-201": Object.freeze({
    id: "R-201",
    engineKey: null,
    category: "threat_hunting",
    executable: false,
    name: "Off-hours successful login hunt",
    description: "A hunting hypothesis for successful authentication outside an organization's expected operating hours.",
    technique: "T1078 · Valid Accounts",
    severity: "medium",
    version: "Example",
    status: "draft",
    owner: "Threat Hunting",
    lastUpdated: "Not deployed",
    criteria: "Successful logins observed between 00:00 and 06:00",
    input: "SUCCESS login_attempt events with a timestamp",
    groupBy: "Username and source IP",
    query: "status=SUCCESS event_type=login_attempt | hour(timestamp) in 00..06 | group by username, source_ip",
    response: "Validate the user's schedule and source location before escalating anomalous access.",
  }),
  "R-202": Object.freeze({
    id: "R-202",
    engineKey: null,
    category: "emerging_threat",
    executable: false,
    name: "Emerging APT indicator correlation",
    description: "A template for correlating newly published campaign indicators with normalized network activity.",
    technique: "T1071 · Application Layer Protocol",
    severity: "high",
    version: "Example",
    status: "template",
    owner: "Threat Intelligence",
    lastUpdated: "Awaiting indicators",
    criteria: "Network destination matches a validated campaign indicator",
    input: "Network events and a reviewed indicator set",
    groupBy: "Destination address",
    query: "event_type=network_connection | destination_ip in validated_campaign_indicators",
    response: "Validate the indicator and affected asset, then scope related communication before containment.",
  }),
  "R-203": Object.freeze({
    id: "R-203",
    engineKey: null,
    category: "compliance",
    executable: false,
    name: "Privileged authentication audit check",
    description: "An audit-oriented template for reviewing privileged access without asserting a security incident.",
    technique: "T1078.003 · Local Accounts",
    severity: "low",
    version: "Example",
    status: "template",
    owner: "Governance and Compliance",
    lastUpdated: "Awaiting control mapping",
    criteria: "Privileged authentication activity is available for control review",
    input: "Authentication events with privilege context",
    groupBy: "Privileged identity",
    query: "event_type=login_attempt privilege=admin | group by username",
    response: "Compare activity with approved access records and retain evidence according to policy.",
  }),
  "R-204": Object.freeze({
    id: "R-204",
    engineKey: null,
    category: "placeholder",
    executable: false,
    name: "Custom detection placeholder",
    description: "A reserved definition that demonstrates where a future custom detection can be documented.",
    technique: "Not assigned",
    severity: "low",
    version: "Example",
    status: "placeholder",
    owner: "Unassigned",
    lastUpdated: "Not designed",
    criteria: "Detection criteria have not been defined",
    input: "Not defined",
    groupBy: "Not defined",
    query: "// Add detection logic before implementation",
    response: "Assign an owner, validate the data source, and define testable criteria before implementation.",
  }),
});

export const SAMPLE_DETECTION_RULE_IDS = Object.freeze(
  Object.keys(SAMPLE_DETECTION_RULES),
);

export function summarizeRuleActivity(ruleId, alerts = []) {
  const safeAlerts = Array.isArray(alerts) ? alerts : [];
  const matches = safeAlerts.filter((alert) => alert?.ruleId === ruleId);
  const active = matches.filter((alert) => !["closed", "resolved"].includes(
    String(alert?.status || "").toLowerCase(),
  ));
  const timestamps = matches
    .map((alert) => new Date(alert?.observedAt || alert?.createdAt || "").getTime())
    .filter(Number.isFinite);

  return {
    active: active.length,
    latest: timestamps.length ? new Date(Math.max(...timestamps)).toISOString() : null,
    total: matches.length,
  };
}
