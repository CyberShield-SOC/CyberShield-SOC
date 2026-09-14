import {
  alertRecords,
  aiAnalysisSeed,
  analystNotesSeed,
  dashboardData,
  incidentRecords,
  securityEvents,
  workspaceSettings,
} from "../data/mockData.js";
import { TEST_DELAY_MS, TEST_RESULT } from "../data/ruleBuilderMockData.js";
import { CURRENT_DETECTION_RULES, RULE_ID_BY_ENGINE_KEY } from "../data/detectionRulePack.js";
import { detectionRuleApiBody } from "../utils/ruleConfig.js";
import { restoreStoredNotes, restoreStoredSettings } from "../utils/storageValidation.js";
import { isTerminalIncidentStatus } from "../utils/incidentWorkflow.js";
import { createInFlightDeduper } from "../utils/asyncUtils.js";
import { apiRequest, isBackendConfigured } from "../../services/apiClient.js";

const NOTES_STORAGE_KEY = "cybershield-session-notes";
const SETTINGS_STORAGE_KEY = "cybershield-session-settings";
const USERS_STORAGE_KEY = "cybershield-session-users";
const CUSTOM_RULES_STORAGE_KEY = "cybershield-session-custom-rules";
const BUILT_IN_RULES_STORAGE_KEY = "cybershield-session-built-in-rules";
const CUSTOM_RULE_NUMBER_BASE = 108; // R-101..R-108 are the built-in rules
const SEVERITY_RISK = Object.freeze({ critical: 96, high: 82, medium: 58, low: 30, info: 10 });
// Backend rule name -> catalog ID (R-101.., R-A01..), from detectionRulePack.js.
const RULE_IDS = RULE_ID_BY_ENGINE_KEY;
let apiNotesSnapshot = new Map();
const runApiReadOnce = createInFlightDeduper();

const DEFAULT_USER_ROLES = Object.freeze([
  { id: 1, name: "Admin", description: "Manages users, roles, and workspace settings." },
  { id: 2, name: "Analyst", description: "Investigates alerts and manages incidents." },
  { id: 3, name: "Viewer", description: "Reviews security data without modifying it." },
]);
const VALID_WORKSPACE_ROLES = new Set(DEFAULT_USER_ROLES.map((role) => role.name));
const UPLOAD_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

const DEFAULT_WORKSPACE_USERS = Object.freeze([
  { id: 1, username: "admin", email: "admin@cybershield.io", fullName: "CyberShield Admin", isActive: true, role: "Admin" },
  { id: 2, username: "analyst", email: "analyst@cybershield.io", fullName: "Yugal P.", isActive: true, role: "Analyst" },
  { id: 3, username: "marvellous", email: "marvellous@cybershield.io", fullName: "Marvellous", isActive: true, role: "Analyst" },
  { id: 4, username: "viewer", email: "viewer@cybershield.io", fullName: "Workspace Viewer", isActive: true, role: "Viewer" },
]);

function clone(value) {
  return structuredClone(value);
}

function wait(milliseconds) {
  return new Promise((resolve) => window.setTimeout(resolve, milliseconds));
}

function displayId(prefix, value) {
  return `${prefix}-${String(value).padStart(4, "0")}`;
}

export function backendId(value) {
  const match = String(value ?? "").match(/(\d+)$/);
  const parsed = match ? Number(match[1]) : null;
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : null;
}

function requireBackendId(value, label) {
  const id = backendId(value);
  if (!id) throw new Error(`${label} is invalid. Refresh the workspace and try again.`);
  return id;
}

function safeValidationDetail(payload) {
  const detail = payload?.detail;
  if (typeof detail === "object" && typeof detail?.error === "string") {
    return detail.error.slice(0, 240);
  }
  if (typeof detail === "string") return detail.slice(0, 240);
  if (Array.isArray(detail)) {
    // FastAPI's default Pydantic validation-error shape: a list of
    // {msg: "Value error, <message>", ...}. Strip Pydantic's prefix so a
    // policy rejection (e.g. from backend/app/validation/passwords.py)
    // reads as a plain sentence instead of a generic 422 fallback.
    const messages = detail
      .map((item) => String(item?.msg || "").replace(/^value error,\s*/i, "").trim())
      .filter(Boolean);
    if (messages.length) return messages.join(" ").slice(0, 240);
  }
  return "";
}

export function getRepositoryErrorMessage(status, payload = {}) {
  const validationDetail = safeValidationDetail(payload);
  if ([400, 409, 413, 415, 422].includes(status) && validationDetail) return validationDetail;
  if (status === 401) return "Your session expired. Sign in again to continue.";
  if (status === 403) return "Your account does not have permission for this action.";
  if (status === 404) return "That record no longer exists. Refresh the workspace and try again.";
  if (status === 409) return "That record already exists or changed. Refresh and try again.";
  if (status === 413) return "The selected file is larger than the upload limit.";
  if (status === 415) return "Choose a supported .log, .csv, .txt, .json, or .jsonl file.";
  if (status === 422) return "Some submitted values were invalid. Review the form and try again.";
  if (status >= 500) return "The service is temporarily unavailable. Try again shortly.";
  return `The service could not complete the request (${status}).`;
}

function responseArray(payload, key) {
  const value = payload?.[key];
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value)) {
    throw new Error("The service returned an invalid response. Refresh and try again.");
  }
  return value;
}

function normalizeUploadBatch(payload) {
  const upload = payload?.upload;
  const uploadId = String(upload?.upload_id || "").trim();
  if (!upload || !UPLOAD_ID_PATTERN.test(uploadId)) {
    throw new Error("The service returned an invalid upload batch.");
  }

  const rawAlerts = responseArray(payload, "alerts");
  return {
    uploadId,
    filename: String(upload.filename || "Unknown file"),
    format: String(upload.format || "unknown"),
    uploadedAt: String(upload.uploaded_at || ""),
    storedEntries: Math.max(0, Number(upload.stored_entries) || 0),
    storedAlerts: Math.max(0, Number(upload.stored_alerts) || 0),
    events: responseArray(payload, "logs").map((log) => normalizeEvent(log, rawAlerts)),
    alerts: rawAlerts.map((alert) => normalizeAlert(alert, payload)),
  };
}

function readSessionNotes() {
  try {
    const stored = window.sessionStorage.getItem(NOTES_STORAGE_KEY);
    if (!stored) return clone(analystNotesSeed);
    return restoreStoredNotes(JSON.parse(stored), analystNotesSeed);
  } catch {
    return clone(analystNotesSeed);
  }
}

function writeSessionNotes(notes) {
  try {
    window.sessionStorage.setItem(NOTES_STORAGE_KEY, JSON.stringify(notes));
  } catch {
    // The provider keeps the current in-memory copy when session storage is unavailable.
  }
}

function readSessionSettings() {
  try {
    const stored = window.sessionStorage.getItem(SETTINGS_STORAGE_KEY);
    if (!stored) return clone(workspaceSettings);
    return restoreStoredSettings(JSON.parse(stored), workspaceSettings);
  } catch {
    return clone(workspaceSettings);
  }
}

function writeSessionSettings(settings) {
  try {
    window.sessionStorage.setItem(SETTINGS_STORAGE_KEY, JSON.stringify(settings));
  } catch {
    // Settings remain available in memory when session storage is unavailable.
  }
}

function normalizeAssignableUser(user) {
  const id = Number(user?.id);
  const username = String(user?.username || "").trim();
  if (!Number.isSafeInteger(id) || id <= 0 || !username) {
    throw new Error("The service returned an invalid assignable user record.");
  }
  return {
    id,
    username,
    fullName: String(user?.fullName ?? user?.full_name ?? "").trim(),
    role: String(user?.role || "").trim(),
  };
}

export function normalizeWorkspaceUser(user) {
  const id = Number(user?.id);
  const username = String(user?.username || "").trim();
  const email = String(user?.email || "").trim().toLowerCase();
  const role = String(user?.role || "Viewer").trim();
  if (!Number.isSafeInteger(id) || id <= 0 || !username || !email || !VALID_WORKSPACE_ROLES.has(role)) {
    throw new Error("The service returned an invalid user record.");
  }
  return {
    id,
    username,
    email,
    fullName: String(user?.fullName ?? user?.full_name ?? "").trim(),
    isActive: Boolean(user?.isActive ?? user?.is_active),
    role,
  };
}

function readSessionUsers() {
  try {
    const parsed = JSON.parse(window.sessionStorage.getItem(USERS_STORAGE_KEY) || "null");
    if (!Array.isArray(parsed)) return clone(DEFAULT_WORKSPACE_USERS);
    return parsed.map(normalizeWorkspaceUser);
  } catch {
    return clone(DEFAULT_WORKSPACE_USERS);
  }
}

function writeSessionUsers(users) {
  try {
    window.sessionStorage.setItem(USERS_STORAGE_KEY, JSON.stringify(users));
  } catch {
    // The current in-memory result remains usable if browser storage is blocked.
  }
}

function readSessionCustomRules() {
  try {
    const parsed = JSON.parse(window.sessionStorage.getItem(CUSTOM_RULES_STORAGE_KEY) || "null");
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function writeSessionCustomRules(rules) {
  try {
    window.sessionStorage.setItem(CUSTOM_RULES_STORAGE_KEY, JSON.stringify(rules));
  } catch {
    // The current in-memory result remains usable if browser storage is blocked.
  }
}

function nextMockRuleId(rules) {
  const highest = rules.reduce((max, rule) => {
    const match = String(rule.rule_id || "").match(/^R-(\d+)$/);
    return match ? Math.max(max, Number(match[1])) : max;
  }, CUSTOM_RULE_NUMBER_BASE);
  return `R-${highest + 1}`;
}

function readSessionBuiltInRuleOverrides() {
  try {
    const parsed = JSON.parse(window.sessionStorage.getItem(BUILT_IN_RULES_STORAGE_KEY) || "null");
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
}

function writeSessionBuiltInRuleOverrides(overrides) {
  try {
    window.sessionStorage.setItem(BUILT_IN_RULES_STORAGE_KEY, JSON.stringify(overrides));
  } catch {
    // The current in-memory result remains usable if browser storage is blocked.
  }
}

const THREAT_FEEDS_STORAGE_KEY = "cybershield-session-threat-feeds";

function readSessionThreatFeeds() {
  try {
    const parsed = JSON.parse(window.sessionStorage.getItem(THREAT_FEEDS_STORAGE_KEY) || "[]");
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function writeSessionThreatFeeds(feeds) {
  try {
    window.sessionStorage.setItem(THREAT_FEEDS_STORAGE_KEY, JSON.stringify(feeds));
  } catch {
    // Keep working in memory when storage is blocked.
  }
}

export function normalizeThreatFeed(feed) {
  const byType = plainObject(feed?.by_type || feed?.byType);
  return {
    source: String(feed?.source || ""),
    indicatorCount: Number(feed?.indicator_count ?? feed?.indicatorCount) || 0,
    updatedAt: feed?.updated_at || feed?.updatedAt || null,
    byType: { ip: Number(byType.ip) || 0, cidr: Number(byType.cidr) || 0, domain: Number(byType.domain) || 0 },
  };
}

const HEARTBEAT_STATUSES = new Set(["reporting", "silent", "learning"]);

export function normalizeHostHeartbeat(host) {
  const status = String(host?.status || "").toLowerCase();
  return {
    hostname: String(host?.hostname || ""),
    status: HEARTBEAT_STATUSES.has(status) ? status : "learning",
    lastSeenAt: host?.last_seen_at || null,
    firstSeenAt: host?.first_seen_at || null,
    eventCount: Number(host?.event_count) || 0,
    cadenceSeconds: host?.cadence_seconds == null ? null : Number(host.cadence_seconds),
    silenceThresholdSeconds: Number(host?.silence_threshold_seconds) || 0,
    silentForSeconds: Number(host?.silent_for_seconds) || 0,
  };
}

async function request(path, options = {}) {
  const payload = await apiRequest(path, {
    ...options,
    errorMessage: getRepositoryErrorMessage,
  });
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new Error("The service returned an invalid response. Refresh and try again.");
  }
  return payload;
}

function normalizeAlertStatus(status) {
  return ({ NEW: "new", REVIEWING: "investigating", ESCALATED: "escalated", CLOSED: "resolved" })[
    String(status || "").toUpperCase()
  ] || String(status || "unknown").trim().toLowerCase() || "unknown";
}

export function apiAlertStatus(status) {
  return ({
    new: "NEW",
    investigating: "REVIEWING",
    escalated: "ESCALATED",
    resolved: "CLOSED",
  })[status] || null;
}

function normalizeIncidentStatus(status) {
  return ({ OPEN: "open", INVESTIGATING: "investigating", RESOLVED: "resolved", FALSE_POSITIVE: "false positive", CLOSED: "resolved" })[
    String(status || "").toUpperCase()
  ] || String(status || "unknown").trim().toLowerCase() || "unknown";
}

export function apiIncidentStatus(status) {
  return ({
    open: "OPEN",
    investigating: "INVESTIGATING",
    resolved: "RESOLVED",
    "false positive": "FALSE_POSITIVE",
  })[status] || null;
}

function evidenceId(log) {
  return `EVT-${log.id || `${String(log.upload_id || "upload").slice(0, 8)}-${log.line_number || 0}`}`;
}

function normalizeEvent(log, alerts = []) {
  const alert = alerts.find((item) => (
    item.upload_id === log.upload_id
    && (item.matched_line_numbers || []).includes(log.line_number)
  ));
  const severity = String(alert?.severity || log.severity || "info").toLowerCase();
  const status = String(log.status || "unknown").toLowerCase();
  const ruleId = RULE_IDS[alert?.rule] || alert?.rule || "No detection rule";

  return {
    id: evidenceId(log),
    backendId: log.id,
    sourceAlertId: alert?.id || null,
    timestamp: log.timestamp || new Date().toISOString(),
    ingestedAt: log.ingested_at || log.timestamp || new Date().toISOString(),
    source: log.source_filename || "ingested log",
    sourceIp: log.ip || "Unknown",
    user: log.username || "Unknown",
    event: log.event || "Security event",
    severity,
    status,
    risk: SEVERITY_RISK[severity] ?? SEVERITY_RISK.info,
    rule: ruleId,
    message: log.raw_message || alert?.description || "Normalized security event.",
    countryCode: log.country_code || log.geo?.country_code || "",
    country: log.country || log.country_name || log.geo?.country || "",
  };
}

/**
 * Shape reserved for a future ML anomaly-detection result attached to an
 * alert: { score: 0-100, label: string, explanation: string,
 * contributingFactors: string[] }. Returns null when the source has none of
 * these fields, which every UI reader must treat as "no ML insight yet".
 */
function normalizeMlInsight(source) {
  if (!source || typeof source !== "object") return null;
  const score = Number(source.score ?? source.anomaly_score);
  const explanation = String(source.explanation || "").trim();
  if (!Number.isFinite(score) && !explanation) return null;
  return {
    score: Number.isFinite(score) ? Math.max(0, Math.min(100, score)) : null,
    label: String(source.label || source.verdict || "").trim(),
    explanation,
    contributingFactors: Array.isArray(source.contributing_factors || source.contributingFactors)
      ? (source.contributing_factors || source.contributingFactors).map(String)
      : [],
  };
}

function normalizeAlert(alert, latest = null) {
  const latestLogs = latest?.logs || [];
  const matchedLogs = latest?.upload?.upload_id === alert.upload_id
    ? latestLogs.filter((log) => (alert.matched_line_numbers || []).includes(log.line_number))
    : [];
  const severity = String(alert.severity || "LOW").toLowerCase();
  const ruleId = RULE_IDS[alert.rule] || String(alert.rule || "detection_rule").toUpperCase();

  return {
    id: displayId("ALT", alert.id),
    backendId: alert.id,
    sourceAlertId: alert.id,
    eventId: matchedLogs[0] ? evidenceId(matchedLogs[0]) : "",
    title: alert.title,
    severity,
    status: normalizeAlertStatus(alert.status),
    source: latest?.upload?.upload_id === alert.upload_id
      ? latest.upload.filename || "ingested log"
      : "ingested log",
    sourceIp: alert.source_ip || "Unknown",
    user: alert.username || "Unknown",
    hostname: alert.hostname || "",
    mitreTechnique: alert.mitre_technique || "",
    confidence: Number.isFinite(Number(alert.confidence)) && alert.confidence !== null ? Number(alert.confidence) : null,
    entityType: alert.entity_type || "",
    entityId: alert.entity_id || "",
    evidence: plainObject(alert.evidence),
    risk: SEVERITY_RISK[severity] ?? SEVERITY_RISK.low,
    // Workflow age follows when the persisted alert was created; firstSeen is
    // the evidence observation time and may legitimately predate ingestion.
    createdAt: alert.created_at || alert.first_seen,
    observedAt: alert.first_seen || alert.created_at,
    firstSeen: alert.first_seen || alert.created_at,
    lastSeen: alert.last_seen || alert.first_seen || alert.created_at,
    timeWindowSeconds: Number(alert.time_window_seconds) || 0,
    ruleId,
    ruleName: String(alert.rule || "Detection rule").replaceAll("_", " "),
    summary: alert.description || "Security rule triggered.",
    reason: alert.reason || alert.description || "Security rule triggered.",
    playbook: alert.response_playbook || alert.playbook || null,
    actionResults: alert.action_results || alert.actionResults || {},
    // Placeholder for a future ML anomaly-detection integration: no backend
    // field populates this today, so it normalizes to null and every reader
    // must treat it as optional. See docs/backend_data_requirements_for_ml.md.
    mlInsight: normalizeMlInsight(alert.ml_insight || alert.mlInsight),
    assignee: "Unassigned",
    evidenceIds: matchedLogs.map(evidenceId),
    countryCode: alert.country_code || alert.geo?.country_code || "",
    country: alert.country || alert.country_name || alert.geo?.country || "",
  };
}

const ALWAYS_TUNABLE = Object.freeze(["enabled", "confidence", "cooldown_seconds"]);

function plainObject(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : {};
}

export function normalizeBuiltInRule(rule) {
  const config = plainObject(rule?.config);
  const tunables = Array.isArray(rule?.tunables) ? rule.tunables.map(String) : [...ALWAYS_TUNABLE];
  return {
    engineKey: String(rule?.name || ""),
    id: RULE_IDS[rule?.name] || String(rule?.name || ""),
    description: rule?.description || "",
    severity: String(rule?.severity || "MEDIUM").toLowerCase(),
    mitreTechnique: rule?.mitre_technique || null,
    entityType: rule?.entity_type || null,
    tunables,
    defaultParams: plainObject(rule?.default_params),
    enabled: config.enabled !== false,
    threshold: config.threshold ?? null,
    failThreshold: config.fail_threshold ?? null,
    windowSeconds: config.window_seconds ?? null,
    successWindowSeconds: config.success_window_seconds ?? null,
    cooldownSeconds: config.cooldown_seconds ?? null,
    confidence: config.confidence ?? null,
    allowlist: Array.isArray(config.allowlist) ? config.allowlist.map(String) : (tunables.includes("allowlist") ? [] : null),
    startHour: config.start_hour ?? null,
    endHour: config.end_hour ?? null,
    params: plainObject(config.params),
  };
}

/** What sample mode reports for a catalog rule: its defaults plus session overrides. */
function sampleBuiltInRule(rule, overrides = {}) {
  const defaults = rule.defaults || {};
  const { params: defaultParams = {}, ...defaultConfig } = defaults;
  const tunables = [...new Set([...Object.keys(defaultConfig), ...(Object.keys(defaultParams).length ? ["params"] : []), ...ALWAYS_TUNABLE])];
  return normalizeBuiltInRule({
    name: rule.engineKey,
    description: rule.description,
    severity: rule.severity.toUpperCase(),
    mitre_technique: String(rule.technique || "").split(" ")[0] || null,
    tunables,
    default_params: defaultParams,
    config: {
      enabled: true,
      confidence: null,
      ...defaultConfig,
      ...overrides,
      params: { ...defaultParams, ...(overrides.params || {}) },
    },
  });
}

function normalizeCustomRule(rule) {
  return {
    id: String(rule.rule_id || rule.ruleId || ""),
    backendId: rule.id,
    name: rule.name,
    category: rule.category,
    severity: String(rule.severity || "medium").toLowerCase(),
    tactic: rule.tactic || "",
    conditions: (rule.conditions || []).map((condition) => ({
      field: condition.field,
      operator: condition.operator,
      value: condition.value,
    })),
    groupBy: rule.group_by || rule.groupBy || "none",
    windowSeconds: Number(rule.window_seconds ?? rule.windowSeconds) || 600,
    actions: rule.actions || {},
    status: String(rule.status || "draft").toLowerCase(),
    dsl: rule.dsl || "",
    executable: rule.executable !== false,
    createdAt: rule.created_at || rule.createdAt || "",
    updatedAt: rule.updated_at || rule.updatedAt || "",
  };
}

function customRuleApiPayload(rule) {
  return {
    name: rule.name,
    category: rule.category,
    severity: rule.severity,
    tactic: rule.tactic || null,
    conditions: rule.conditions,
    group_by: rule.groupBy || "none",
    window_seconds: rule.windowSeconds,
    actions: rule.actions || {},
    ...(rule.status ? { status: rule.status.toUpperCase() } : {}),
    ...(rule.dsl ? { dsl: rule.dsl } : {}),
  };
}

function normalizeIncident(incident, alerts = [], latest = null) {
  const sourceAlert = alerts.find((alert) => alert.id === incident.source_alert_id);
  const normalizedAlert = sourceAlert ? normalizeAlert(sourceAlert, latest) : null;
  const status = normalizeIncidentStatus(incident.status);
  const terminal = isTerminalIncidentStatus(status);
  const completedByUserId = terminal ? Number(incident.updated_by_user_id) || null : null;
  const completedAt = terminal ? incident.closed_at || incident.resolved_at || incident.updated_at : null;
  return {
    id: displayId("INC", incident.id),
    backendId: incident.id,
    sourceAlertId: incident.source_alert_id,
    title: incident.title,
    assignedUserId: incident.assigned_user_id || null,
    owner: incident.assigned_user_id ? `User ${incident.assigned_user_id}` : "Unassigned",
    priority: String(incident.priority || "LOW").toLowerCase(),
    status,
    updated: incident.updated_at,
    completedAt,
    completedByUserId,
    completedBy: completedByUserId ? `User ${completedByUserId}` : null,
    sla: terminal ? "Completed" : "Within target",
    summary: incident.description,
    playbook: incident.response_playbook || incident.playbook || normalizedAlert?.playbook || null,
    eventIds: normalizedAlert?.evidenceIds || [],
  };
}

function normalizeNote(note, incident = null) {
  const createdAt = note.created_at;
  const incidentId = incident?.id || note.incident_id;
  return {
    id: displayId("NOTE", note.id),
    backendId: note.id,
    title: note.title || "Analyst note",
    body: note.body,
    author: `User ${note.author_user_id}`,
    createdAt,
    updatedAt: note.updated_at,
    tags: note.tags || [],
    linkedType: "incident",
    linkedId: displayId("INC", incidentId),
    linkedBackendId: incidentId,
    pinned: Boolean(note.pinned),
    archived: Boolean(note.archived),
    versions: [{ version: 1, at: createdAt, author: `User ${note.author_user_id}`, summary: "Stored incident note" }],
  };
}

function buildDashboard(events, alerts, incidents) {
  const severityOrder = ["critical", "high", "medium", "low"];
  const alertVolume = Array.from({ length: 12 }, (_, index) => ({
    label: `${String(index * 2).padStart(2, "0")}:00`,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  }));
  alerts.forEach((alert) => {
    const hour = new Date(alert.createdAt).getHours();
    const bucket = Number.isFinite(hour) ? alertVolume[Math.floor(hour / 2)] : null;
    if (bucket && severityOrder.includes(alert.severity)) bucket[alert.severity] += 1;
  });
  const severity = severityOrder.map((level) => ({
    label: level[0].toUpperCase() + level.slice(1),
    value: alerts.filter((alert) => alert.severity === level).length,
    color: `var(--severity-${level})`,
  }));
  const uniqueRules = new Set(alerts.map((alert) => alert.ruleId).filter(Boolean)).size;

  return {
    liveRate: null,
    liveRateLabel: "Latest upload synced",
    stats: [
      { label: "Events ingested (24h)", value: String(events.length), trend: "Latest persisted upload" },
      { label: "Active alerts", value: String(alerts.filter((item) => item.status !== "resolved").length), trend: `${alerts.filter((item) => item.status === "new").length} new`, tone: "critical" },
      { label: "Open incidents", value: String(incidents.filter((item) => !isTerminalIncidentStatus(item.status)).length), trend: `${incidents.filter((item) => isTerminalIncidentStatus(item.status)).length} completed`, tone: "success" },
      { label: "Detection rules triggered", value: String(uniqueRules), trend: "Across persisted alerts" },
    ],
    alertVolume,
    severity,
    ingestionTrend: [0, 0, 0, 0, 0, 0, events.length],
    ingestionLabels: ["Day -6", "Day -5", "Day -4", "Day -3", "Day -2", "Yesterday", "Latest"],
    coverage: [{ label: "Triggered rules", value: uniqueRules, total: Math.max(uniqueRules, 1) }],
  };
}

const mockRepository = {
  mode: "mock",
  async getHealth() { await wait(60); return { status: "demo", timestamp: new Date().toISOString() }; },
  async getDashboard() { await wait(120); return clone(dashboardData); },
  async getEvents() { await wait(140); return clone(securityEvents); },
  async getUploadHistory() {
    await wait(100);
    return { uploads: [], pagination: { page: 1, pageSize: 25, total: 0, pageCount: 1 } };
  },
  async getUploadBatch() {
    throw new Error("Upload history requires the connected backend.");
  },
  async getAlerts() { await wait(130); return clone(alertRecords); },
  async getIncidents() { await wait(140); return clone(incidentRecords); },
  async getNotes() { await wait(90); return readSessionNotes(); },
  async getSettings() { await wait(100); return readSessionSettings(); },
  async getUsers() { await wait(100); return readSessionUsers(); },
  async getUserRoles() { await wait(70); return clone(DEFAULT_USER_ROLES); },
  async getAssignableUsers() {
    await wait(80);
    return readSessionUsers()
      .filter((sessionUser) => sessionUser.isActive)
      .map((sessionUser) => ({
        id: sessionUser.id,
        username: sessionUser.username,
        fullName: sessionUser.fullName,
        role: sessionUser.role,
      }));
  },
  async saveSettings(settings) { await wait(140); writeSessionSettings(settings); return clone(settings); },
  async saveNotes(notes) { await wait(80); writeSessionNotes(notes); return clone(notes); },
  async deleteNote(noteId) {
    await wait(80);
    const next = readSessionNotes().filter((note) => note.id !== noteId);
    writeSessionNotes(next);
    return { success: true };
  },
  async updateAlertStatus(alertId, status) { await wait(100); return { id: alertId, status }; },
  async updateIncidentStatus(incidentId, status) {
    await wait(100);
    const updated = new Date().toISOString();
    const terminal = isTerminalIncidentStatus(status);
    return { id: incidentId, status, updated, completedAt: terminal ? updated : null, completedBy: null, completedByUserId: null };
  },
  async createIncident(incident) { await wait(120); return clone(incident); },
  async updateIncidentAssignee(incidentId, assignedUserId) {
    await wait(100);
    return { id: incidentId, assignedUserId: assignedUserId || null };
  },
  async createUser(user) {
    await wait(100);
    const users = readSessionUsers();
    const username = String(user?.username || "").trim();
    const email = String(user?.email || "").trim().toLowerCase();
    const role = String(user?.role || "").trim();
    if (!username || !email || !VALID_WORKSPACE_ROLES.has(role)) throw new Error("Review the new user details and try again.");
    if (users.some((item) => item.username.toLowerCase() === username.toLowerCase() || item.email.toLowerCase() === email)) {
      throw new Error("A user already exists with that username or email.");
    }
    const created = {
      id: Math.max(0, ...users.map((item) => item.id)) + 1,
      username,
      email,
      fullName: String(user?.fullName || "").trim(),
      isActive: true,
      role,
    };
    writeSessionUsers([...users, created]);
    return clone(created);
  },
  async updateUser(userId, updates) {
    await wait(100);
    const users = readSessionUsers();
    const numericId = Number(userId);
    const target = users.find((item) => item.id === numericId);
    if (!target) throw new Error("That user no longer exists.");

    const nextUser = {
      ...target,
      username: String(updates?.username || "").trim(),
      email: String(updates?.email || "").trim().toLowerCase(),
      fullName: String(updates?.fullName || "").trim(),
      role: String(updates?.role || "").trim(),
      isActive: Boolean(updates?.isActive),
    };
    if (!nextUser.username || !nextUser.email || !VALID_WORKSPACE_ROLES.has(nextUser.role)) {
      throw new Error("Review the user details and try again.");
    }
    if (users.some((item) => item.id !== numericId && (
      item.username.toLowerCase() === nextUser.username.toLowerCase()
      || item.email.toLowerCase() === nextUser.email
    ))) {
      throw new Error("A user already exists with that username or email.");
    }
    if (
      target.role === "Admin"
      && target.isActive
      && (!nextUser.isActive || nextUser.role !== "Admin")
      && users.filter((item) => item.role === "Admin" && item.isActive).length <= 1
    ) {
      throw new Error("Cannot remove the final active Admin.");
    }

    const next = users.map((item) => item.id === numericId ? nextUser : item);
    writeSessionUsers(next);
    return clone(nextUser);
  },
  async resetUserPassword(userId, password) {
    await wait(120);
    const target = readSessionUsers().find((item) => item.id === Number(userId));
    if (!target) throw new Error("That user no longer exists.");
    if (String(password || "").length < 12 || String(password).length > 256) {
      throw new Error("Use a password between 12 and 256 characters.");
    }
    // Sample mode deliberately validates and discards credentials; it never
    // emulates authentication by storing plaintext passwords in the browser.
    return { success: true, sessionsRevoked: 0, user: clone(target) };
  },
  async revokeUserSessions(userId) {
    await wait(100);
    const target = readSessionUsers().find((item) => item.id === Number(userId));
    if (!target) throw new Error("That user no longer exists.");
    return { success: true, sessionsRevoked: 0, user: clone(target) };
  },
  async updateUserRole(userId, role) {
    await wait(100);
    const users = readSessionUsers();
    if (!VALID_WORKSPACE_ROLES.has(role)) throw new Error("Select a supported workspace role.");
    const target = users.find((item) => item.id === Number(userId));
    if (!target) throw new Error("That user no longer exists.");
    if (target.role === "Admin" && target.isActive && role !== "Admin" && users.filter((item) => item.role === "Admin" && item.isActive).length <= 1) throw new Error("Cannot remove the final active Admin.");
    const next = users.map((item) => item.id === Number(userId) ? { ...item, role } : item);
    writeSessionUsers(next);
    return clone(next.find((item) => item.id === Number(userId)));
  },
  async updateUserActive(userId, isActive) {
    await wait(100);
    const users = readSessionUsers();
    const target = users.find((item) => item.id === Number(userId));
    if (!target) throw new Error("That user no longer exists.");
    if (target.role === "Admin" && target.isActive && !isActive && users.filter((item) => item.role === "Admin" && item.isActive).length <= 1) throw new Error("Cannot remove the final active Admin.");
    const next = users.map((item) => item.id === Number(userId) ? { ...item, isActive: Boolean(isActive) } : item);
    writeSessionUsers(next);
    return clone(next.find((item) => item.id === Number(userId)));
  },
  async uploadLog() { throw new Error("Uploads require the connected backend."); },
  async runAiAnalysis({ subject }) { await wait(760); return { ...clone(aiAnalysisSeed), subject: subject || aiAnalysisSeed.subject }; },
  async getCustomRules() {
    await wait(100);
    const rules = readSessionCustomRules();
    return {
      rules: rules.map(normalizeCustomRule),
      nextRuleId: nextMockRuleId(rules),
    };
  },
  async getDetectionRules() {
    await wait(80);
    const overrides = readSessionBuiltInRuleOverrides();
    return Object.values(CURRENT_DETECTION_RULES).map((rule) => sampleBuiltInRule(rule, overrides[rule.engineKey]));
  },
  async updateDetectionRule(engineKey, updates) {
    await wait(120);
    const rule = Object.values(CURRENT_DETECTION_RULES).find((item) => item.engineKey === engineKey);
    if (!rule) throw new Error("That detection rule no longer exists.");
    const overrides = readSessionBuiltInRuleOverrides();
    const body = detectionRuleApiBody(updates);
    const current = overrides[engineKey] || {};
    overrides[engineKey] = {
      ...current,
      ...body,
      ...(body.params ? { params: { ...(current.params || {}), ...body.params } } : {}),
    };
    writeSessionBuiltInRuleOverrides(overrides);
    return sampleBuiltInRule(rule, overrides[engineKey]);
  },
  async getThreatIntelFeeds() {
    await wait(80);
    return readSessionThreatFeeds();
  },
  async importThreatIntelFeed({ source, content }) {
    await wait(120);
    const indicators = String(content || "")
      .split(/\r?\n/)
      .map((line) => line.split(/[#;]/, 1)[0].trim().split(/[\s,]+/, 1)[0])
      .filter(Boolean);
    if (!indicators.length) throw new Error("The feed contained no indicators.");
    const feeds = readSessionThreatFeeds().filter((feed) => feed.source !== source);
    feeds.push({ source, indicatorCount: new Set(indicators).size, updatedAt: new Date().toISOString(), byType: {} });
    writeSessionThreatFeeds(feeds);
    return { source, imported: new Set(indicators).size, rejectedLines: 0 };
  },
  async deleteThreatIntelFeed(source) {
    await wait(80);
    writeSessionThreatFeeds(readSessionThreatFeeds().filter((feed) => feed.source !== source));
  },
  async getHostHeartbeats() {
    await wait(80);
    return { checkedAt: new Date().toISOString(), hosts: [] };
  },
  async checkHostSilence() {
    throw new Error("Host silence checks require the connected backend.");
  },
  async createCustomRule(rule) {
    await wait(150);
    const rules = readSessionCustomRules();
    const now = new Date().toISOString();
    const created = {
      id: Math.max(0, ...rules.map((item) => item.id)) + 1,
      rule_id: nextMockRuleId(rules),
      ...customRuleApiPayload(rule),
      status: (rule.status || "draft").toUpperCase(),
      severity: String(rule.severity || "medium").toUpperCase(),
      created_at: now,
      updated_at: now,
    };
    writeSessionCustomRules([created, ...rules]);
    return normalizeCustomRule(created);
  },
  async updateCustomRule(backendId, updates) {
    await wait(120);
    const rules = readSessionCustomRules();
    const target = rules.find((item) => item.id === backendId);
    if (!target) throw new Error("That custom rule no longer exists.");
    Object.assign(target, {
      ...(updates.status ? { status: updates.status.toUpperCase() } : {}),
      ...(updates.name ? { name: updates.name } : {}),
      updated_at: new Date().toISOString(),
    });
    writeSessionCustomRules(rules);
    return normalizeCustomRule(target);
  },
  async deleteCustomRule(backendId) {
    await wait(100);
    writeSessionCustomRules(readSessionCustomRules().filter((item) => item.id !== backendId));
    return { success: true };
  },
  async testCustomRule() {
    await wait(TEST_DELAY_MS);
    return {
      sampledCount: 4200,
      matchCount: TEST_RESULT.matchCount,
      alertCount: TEST_RESULT.matchCount,
      matches: TEST_RESULT.matches.map((match) => ({
        timestamp: match.time,
        ipAddress: match.ipAddress,
        username: match.username,
        eventType: match.eventType,
        status: "FAILED",
        port: null,
      })),
      noise: { label: "LOW", alertsPerDay: 0.4 },
    };
  },
};

const readLatestUpload = () => runApiReadOnce("latest-upload", () => request("/upload/latest"));
const readAlerts = () => runApiReadOnce("alerts", () => request("/alerts"));
const readIncidents = () => runApiReadOnce("incidents", () => request("/incidents"));

async function getApiState() {
  // Dashboard, event, alert, and incident refreshes start together. Sharing
  // identical in-flight GETs prevents duplicate payload parsing and traffic.
  const [latest, alertsPayload, incidentsPayload] = await Promise.all([
    readLatestUpload(),
    readAlerts(),
    readIncidents(),
  ]);
  const rawAlerts = responseArray(alertsPayload, "alerts");
  const latestAlerts = responseArray(latest, "alerts");
  const events = responseArray(latest, "logs").map((log) => normalizeEvent(log, latestAlerts));
  const alerts = rawAlerts.map((alert) => normalizeAlert(alert, latest));
  const incidents = responseArray(incidentsPayload, "incidents").map((incident) => normalizeIncident(incident, rawAlerts, latest));
  return { latest, rawAlerts, events, alerts, incidents };
}

const httpRepository = {
  mode: "api",
  async getHealth() {
    const payload = await request("/health");
    if (payload.status !== "ok" || typeof payload.timestamp !== "string") {
      throw new Error("The API health response was invalid.");
    }
    return payload;
  },
  async getDashboard() {
    const { events, alerts, incidents } = await getApiState();
    return buildDashboard(events, alerts, incidents);
  },
  async getEvents() {
    const latest = await readLatestUpload();
    return responseArray(latest, "logs").map((log) => normalizeEvent(log, responseArray(latest, "alerts")));
  },
  async getUploadHistory({ page = 1, pageSize = 25, query = "" } = {}) {
    const safePage = Math.max(1, Math.trunc(Number(page)) || 1);
    const safePageSize = Math.min(100, Math.max(1, Math.trunc(Number(pageSize)) || 25));
    const safeQuery = String(query || "").trim().slice(0, 100);
    const params = new URLSearchParams({ page: String(safePage), page_size: String(safePageSize) });
    if (safeQuery) params.set("query", safeQuery);
    const payload = await request(`/upload/history?${params.toString()}`);
    const pagination = payload?.pagination || {};
    return {
      uploads: responseArray(payload, "uploads").map((upload) => ({
        uploadId: String(upload.upload_id || ""),
        filename: String(upload.filename || "Unknown file"),
        format: String(upload.format || "unknown"),
        uploadedAt: String(upload.uploaded_at || ""),
        storedEntries: Math.max(0, Number(upload.stored_entries) || 0),
        storedAlerts: Math.max(0, Number(upload.stored_alerts) || 0),
      })),
      pagination: {
        page: Math.max(1, Number(pagination.page) || safePage),
        pageSize: Math.max(1, Number(pagination.page_size) || safePageSize),
        total: Math.max(0, Number(pagination.total) || 0),
        pageCount: Math.max(1, Number(pagination.page_count) || 1),
      },
    };
  },
  async getUploadBatch(uploadId) {
    const safeUploadId = String(uploadId || "").trim();
    if (!UPLOAD_ID_PATTERN.test(safeUploadId)) {
      throw new Error("That uploaded file identifier is invalid. Refresh file history and try again.");
    }
    return normalizeUploadBatch(await request(`/upload/batches/${encodeURIComponent(safeUploadId)}`));
  },
  async getAlerts() {
    const [payload, latest] = await Promise.all([readAlerts(), readLatestUpload()]);
    return responseArray(payload, "alerts").map((alert) => normalizeAlert(alert, latest));
  },
  async getIncidents() {
    const { incidents } = await getApiState();
    return incidents;
  },
  async getNotes() {
    const payload = await request("/notes");
    const notes = responseArray(payload, "notes")
      .map((note) => normalizeNote(note))
      .sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt));
    apiNotesSnapshot = new Map(notes.map((note) => [note.backendId, note]));
    return notes;
  },
  async getUsers() {
    const payload = await request("/users");
    return responseArray(payload, "users").map(normalizeWorkspaceUser);
  },
  async getAssignableUsers() {
    const payload = await request("/users/assignable");
    return responseArray(payload, "users").map(normalizeAssignableUser);
  },
  async getUserRoles() {
    const payload = await request("/users/roles");
    return responseArray(payload, "roles").map((role) => ({
      id: Number(role.id),
      name: String(role.name || "").trim(),
      description: String(role.description || "").trim(),
    })).filter((role) => Number.isSafeInteger(role.id) && role.id > 0 && role.name);
  },
  getSettings: async () => readSessionSettings(),
  async saveSettings(settings) {
    writeSessionSettings(settings);
    return clone(settings);
  },
  async saveNotes(notes) {
    await Promise.all(notes.map(async (note) => {
      const payload = {
        title: note.title,
        body: note.body,
        tags: note.tags,
        pinned: note.pinned,
        archived: note.archived,
      };
      if (!note.backendId) {
        const incidentId = note.linkedBackendId || backendId(note.linkedId);
        if (!incidentId || note.linkedType !== "incident") {
          throw new Error("Connected notes must be linked to an existing incident.");
        }
        await request(`/incidents/${incidentId}/notes`, {
          method: "POST",
          body: JSON.stringify(payload),
        });
        return;
      }
      const previous = apiNotesSnapshot.get(note.backendId);
      if (previous && JSON.stringify(payload) === JSON.stringify({
        title: previous.title,
        body: previous.body,
        tags: previous.tags,
        pinned: previous.pinned,
        archived: previous.archived,
      })) return;
      await request(`/notes/${note.backendId}`, {
        method: "PATCH",
        body: JSON.stringify(payload),
      });
    }));
    return this.getNotes();
  },
  async deleteNote(noteId) {
    return request(`/notes/${requireBackendId(noteId, "Note")}`, { method: "DELETE" });
  },
  async updateAlertStatus(alertId, status) {
    const apiStatus = apiAlertStatus(status);
    if (!apiStatus) throw new Error("That alert status is not supported by the connected service.");
    const payload = await request(`/alerts/${requireBackendId(alertId, "Alert")}`, {
      method: "PATCH",
      body: JSON.stringify({ status: apiStatus }),
    });
    return normalizeAlert(payload.alert);
  },
  async updateIncidentStatus(incidentId, status) {
    const apiStatus = apiIncidentStatus(status);
    if (!apiStatus) throw new Error("That incident status is not supported by the connected service.");
    const payload = await request(`/incidents/${requireBackendId(incidentId, "Incident")}`, {
      method: "PATCH",
      body: JSON.stringify({ status: apiStatus }),
    });
    return normalizeIncident(payload.incident);
  },
  async createIncident(incident) {
    const alertId = incident.sourceAlertId || backendId(incident.alertId);
    if (!alertId) throw new Error("Select a source alert before creating an incident.");
    const assignedUserId = Number(incident.assignedUserId) || null;
    const payload = await request("/incidents", {
      method: "POST",
      body: JSON.stringify({
        alert_id: alertId,
        title: incident.title,
        description: incident.summary,
        priority: String(incident.priority || "medium").toUpperCase(),
        ...(assignedUserId ? { assigned_user_id: assignedUserId } : {}),
      }),
    });
    return {
      ...normalizeIncident(payload.incident),
      eventIds: incident.eventIds || [],
    };
  },
  async updateIncidentAssignee(incidentId, assignedUserId) {
    const payload = await request(`/incidents/${requireBackendId(incidentId, "Incident")}`, {
      method: "PATCH",
      body: JSON.stringify({ assigned_user_id: assignedUserId ? Number(assignedUserId) : null }),
    });
    return normalizeIncident(payload.incident);
  },
  async createUser(user) {
    const payload = await request("/users", {
      method: "POST",
      body: JSON.stringify({
        username: user.username,
        email: user.email,
        password: user.password,
        role: user.role,
        full_name: user.fullName || null,
      }),
    });
    return normalizeWorkspaceUser(payload.user);
  },
  async updateUser(userId, updates) {
    const payload = await request(`/users/${requireBackendId(userId, "User")}`, {
      method: "PATCH",
      body: JSON.stringify({
        username: updates.username,
        email: updates.email,
        full_name: updates.fullName || null,
        role: updates.role,
        is_active: Boolean(updates.isActive),
      }),
    });
    return normalizeWorkspaceUser(payload.user);
  },
  async resetUserPassword(userId, password) {
    const payload = await request(`/users/${requireBackendId(userId, "User")}/password`, {
      method: "PATCH",
      body: JSON.stringify({ new_password: password }),
    });
    return {
      success: payload.success === true,
      sessionsRevoked: Math.max(0, Number(payload.sessions_revoked) || 0),
      user: normalizeWorkspaceUser(payload.user),
    };
  },
  async revokeUserSessions(userId) {
    const payload = await request(`/users/${requireBackendId(userId, "User")}/sessions/revoke`, {
      method: "POST",
    });
    return {
      success: payload.success === true,
      sessionsRevoked: Math.max(0, Number(payload.sessions_revoked) || 0),
      user: normalizeWorkspaceUser(payload.user),
    };
  },
  async updateUserRole(userId, role) {
    const payload = await request(`/users/${requireBackendId(userId, "User")}/role`, {
      method: "PATCH",
      body: JSON.stringify({ role }),
    });
    return normalizeWorkspaceUser(payload.user);
  },
  async updateUserActive(userId, isActive) {
    const payload = await request(`/users/${requireBackendId(userId, "User")}/active`, {
      method: "PATCH",
      body: JSON.stringify({ is_active: Boolean(isActive) }),
    });
    return normalizeWorkspaceUser(payload.user);
  },
  async uploadLog(file) {
    const form = new FormData();
    form.append("logfile", file, file.name);
    return request("/upload", { method: "POST", body: form });
  },
  async runAiAnalysis({ subject }) {
    await wait(420);
    return { ...clone(aiAnalysisSeed), subject: subject || aiAnalysisSeed.subject };
  },
  async getCustomRules() {
    const payload = await request("/custom-rules");
    return {
      rules: responseArray(payload, "rules").map(normalizeCustomRule),
      nextRuleId: payload.next_rule_id || "R-109",
    };
  },
  async getDetectionRules() {
    const payload = await request("/detection/rules");
    return responseArray(payload, "rules").map(normalizeBuiltInRule);
  },
  async updateDetectionRule(engineKey, updates) {
    const payload = await request(`/detection/rules/${encodeURIComponent(engineKey)}`, {
      method: "PATCH",
      body: JSON.stringify(detectionRuleApiBody(updates)),
    });
    return normalizeBuiltInRule(payload.rule);
  },
  async getThreatIntelFeeds() {
    const payload = await request("/threat-intel/feeds");
    return responseArray(payload, "feeds").map(normalizeThreatFeed);
  },
  async importThreatIntelFeed({ source, content, replace = true }) {
    const payload = await request("/threat-intel/feeds", {
      method: "POST",
      body: JSON.stringify({ source, content, replace }),
    });
    return {
      source: payload.source,
      imported: Number(payload.imported) || 0,
      rejectedLines: Number(payload.rejected_lines) || 0,
    };
  },
  async deleteThreatIntelFeed(source) {
    await request(`/threat-intel/feeds/${encodeURIComponent(source)}`, { method: "DELETE" });
  },
  async getHostHeartbeats() {
    const payload = await request("/detection/host-heartbeats");
    return {
      checkedAt: payload.checked_at || null,
      hosts: responseArray(payload, "hosts").map(normalizeHostHeartbeat),
    };
  },
  async checkHostSilence() {
    const payload = await request("/detection/host-silence/check", { method: "POST" });
    return responseArray(payload, "alerts").map((alert) => normalizeAlert(alert));
  },
  async createCustomRule(rule) {
    const payload = await request("/custom-rules", {
      method: "POST",
      body: JSON.stringify(customRuleApiPayload(rule)),
    });
    return normalizeCustomRule(payload.rule);
  },
  async updateCustomRule(ruleId, updates) {
    const numericId = requireBackendId(ruleId, "Custom rule");
    const body = {};
    if (updates.status) body.status = updates.status.toUpperCase();
    if (updates.name) body.name = updates.name;
    const payload = await request(`/custom-rules/${numericId}`, {
      method: "PATCH",
      body: JSON.stringify(body),
    });
    return normalizeCustomRule(payload.rule);
  },
  async deleteCustomRule(ruleId) {
    return request(`/custom-rules/${requireBackendId(ruleId, "Custom rule")}`, { method: "DELETE" });
  },
  async testCustomRule(rule) {
    const payload = await request("/custom-rules/test", {
      method: "POST",
      body: JSON.stringify(customRuleApiPayload(rule)),
    });
    return {
      sampledCount: payload.sampled_count,
      matchCount: payload.match_count,
      alertCount: payload.alert_count,
      matches: (payload.matches || []).map((match) => ({
        timestamp: match.timestamp,
        ipAddress: match.ip_address,
        username: match.username,
        eventType: match.event_type,
        status: match.status,
        port: match.port,
      })),
      noise: {
        label: payload.noise?.label || "LOW",
        alertsPerDay: Number(payload.noise?.alerts_per_day) || 0,
      },
    };
  },
};

export const socRepository = isBackendConfigured ? httpRepository : mockRepository;
