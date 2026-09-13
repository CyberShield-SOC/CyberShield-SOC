/**
 * Fixtures for the Rule Builder screen (custom rule authoring flow). The
 * field catalog, operators, and defaults below mirror what the backend's
 * CustomConditionRule can actually evaluate (see
 * backend/app/detection/rules/custom_condition.py) — only fields that exist
 * on a parsed LogRecord (event_type, status, ip_address, username, port,
 * timestamp) are offered, so every rule saved here is executable, not
 * decorative. RULE_BUILDER_DEFAULTS.ruleId/ruleIdLabel are placeholders shown
 * before the backend assigns the real next id (see GET /custom-rules).
 */
export const RULE_BUILDER_DEFAULTS = Object.freeze({
  ruleId: "R-107",
  category: "generic_detection",
  ruleIdLabel: "R-107 · auto-assigned",
  name: "Off-hours privilege escalation",
  severity: "high",
  tactic: "TA0010",
  groupBy: "ip_address",
  window: "10m",
});

export const SEVERITY_OPTIONS = Object.freeze([
  Object.freeze({ value: "critical", label: "CRITICAL" }),
  Object.freeze({ value: "high", label: "HIGH" }),
  Object.freeze({ value: "medium", label: "MEDIUM" }),
  Object.freeze({ value: "low", label: "LOW" }),
]);

export const MITRE_TACTIC_OPTIONS = Object.freeze([
  Object.freeze({ value: "TA0001", label: "TA0001 · Initial Access" }),
  Object.freeze({ value: "TA0006", label: "TA0006 · Credential Access" }),
  Object.freeze({ value: "TA0007", label: "TA0007 · Discovery" }),
  Object.freeze({ value: "TA0008", label: "TA0008 · Lateral Movement" }),
  Object.freeze({ value: "TA0010", label: "TA0010 · Exfiltration" }),
  Object.freeze({ value: "TA0011", label: "TA0011 · Command and Control" }),
]);

/** Event schema the builder validates against: field name -> value type. */
export const FIELD_CATALOG = Object.freeze([
  Object.freeze({ value: "event_type", type: "string" }),
  Object.freeze({ value: "status", type: "string" }),
  Object.freeze({ value: "ip_address", type: "string" }),
  Object.freeze({ value: "username", type: "string" }),
  Object.freeze({ value: "port", type: "number" }),
  Object.freeze({ value: "timestamp", type: "timestamp" }),
]);

export const OPERATORS_BY_TYPE = Object.freeze({
  string: Object.freeze(["equals", "not equals", "contains", "in"]),
  number: Object.freeze(["equals", ">", "<", "in"]),
  timestamp: Object.freeze(["between", "before", "after"]),
});

export const INITIAL_CONDITIONS = Object.freeze([
  Object.freeze({ field: "event_type", operator: "equals", value: "privilege_escalation" }),
  Object.freeze({ field: "status", operator: "equals", value: "FAILED" }),
  Object.freeze({ field: "timestamp", operator: "between", value: "00:00 – 06:00" }),
]);

export const GROUP_OPTIONS = Object.freeze([
  Object.freeze({ value: "none", label: "no grouping" }),
  Object.freeze({ value: "ip_address", label: "by ip_address" }),
  Object.freeze({ value: "username", label: "by username" }),
]);

export const WINDOW_OPTIONS = Object.freeze([
  Object.freeze({ value: "5m", label: "5 minutes" }),
  Object.freeze({ value: "10m", label: "10 minutes" }),
  Object.freeze({ value: "30m", label: "30 minutes" }),
  Object.freeze({ value: "1h", label: "1 hour" }),
  Object.freeze({ value: "24h", label: "24 hours" }),
]);

/** Matches the backend's allowed CustomRule.window_seconds values exactly. */
export const WINDOW_SECONDS_BY_VALUE = Object.freeze({
  "5m": 300, "10m": 600, "30m": 1800, "1h": 3600, "24h": 86400,
});

/**
 * Action ids match the backend's actions JSON keys 1:1 (see
 * app/schemas/custom_rule.py ACTION_KEYS) so the checkbox state can be sent
 * straight to the API. All four now have real effects on an enabled rule:
 * create_alert persists alerts, notify_slack posts to the configured Slack
 * webhook, auto_incident opens an incident once its threshold is crossed,
 * and suggest_playbook links a response playbook on the alert (see
 * app/repositories/custom_rule_action_repository.py).
 */
export const ACTION_OPTIONS = Object.freeze([
  Object.freeze({ id: "create_alert", label: "Create alert with rule severity", checked: true, muted: false }),
  Object.freeze({ id: "notify_slack", label: "Notify Slack #soc-alerts", checked: true, muted: false }),
  Object.freeze({ id: "auto_incident", label: "Auto-create incident if triggered 3× in 1h", checked: false, muted: true }),
  Object.freeze({ id: "suggest_playbook", label: "Suggest response playbook PB-02 — Data exfiltration", checked: true, muted: false }),
]);

export const TEST_DELAY_MS = 800;

/** Offline-mode fallback shown only when no backend is connected. */
export const TEST_RESULT = Object.freeze({
  windowLabel: "last 24h",
  matchCount: 3,
  matchBadge: "3 MATCHES",
  sampledLabel: "in 4,200 sampled events",
  matches: Object.freeze([
    Object.freeze({ time: "02:14", ipAddress: "10.30.1.99", eventType: "privilege_escalation", username: "administrator" }),
    Object.freeze({ time: "03:41", ipAddress: "10.30.1.99", eventType: "privilege_escalation", username: "administrator" }),
    Object.freeze({ time: "04:05", ipAddress: "198.51.100.7", eventType: "privilege_escalation", username: "svc-backup" }),
  ]),
  noiseTitle: "Estimated noise: LOW",
  noiseDetail: "~0.4 alerts/day at current traffic. Safe to enable.",
});

export const OVERLAP_WARNING = "Runs alongside R-101…R-106 — review for overlapping conditions before enabling.";
