// Presentation helpers for the platform audit trail. The backend stores a
// dotted action name ("user.role.change") plus a small detail object; these
// turn both into plain sentences without ever inventing data.

export const AUDIT_CATEGORY_OPTIONS = Object.freeze([
  { value: "auth", label: "Sign-in and access" },
  { value: "user", label: "Accounts and invites" },
  { value: "rule", label: "Detection rules" },
  { value: "threat_intel", label: "Threat intelligence" },
  { value: "ml", label: "Anomaly models" },
  { value: "log", label: "Log ingestion" },
  { value: "export", label: "Exports" },
]);

const ACTION_LABELS = Object.freeze({
  "auth.login.password": "Password step of sign-in",
  "auth.login.second_factor": "Second factor of sign-in",
  "auth.logout": "Signed out",
  "auth.password_reset.request": "Requested a password reset",
  "auth.password_reset.complete": "Completed a password reset",
  "auth.invite.accept": "Accepted an invite",
  "auth.mfa.enroll": "Turned on authenticator sign-in",
  "auth.mfa.disable": "Turned off authenticator sign-in",
  "auth.mfa.recovery_codes": "Replaced recovery codes",
  "user.invite.create": "Invited a user",
  "user.invite.resend": "Re-sent an invite",
  "user.invite.revoke": "Revoked an invite",
  "user.create": "Created an account",
  "user.update": "Edited an account",
  "user.password.reset": "Reset an account password",
  "user.sessions.revoke": "Revoked an account's sessions",
  "user.role.change": "Changed an account's role",
  "user.active.change": "Enabled or disabled an account",
  "user.mfa.reset": "Reset an account's authenticator",
  "rule.custom.create": "Created a custom rule",
  "rule.custom.update": "Edited a custom rule",
  "rule.custom.delete": "Deleted a custom rule",
  "rule.custom.import": "Imported Sigma rules",
  "rule.builtin.update": "Changed a built-in rule",
  "threat_intel.feed.import": "Imported a threat feed",
  "threat_intel.feed.delete": "Removed a threat feed",
  "ml.model.train": "Trained an anomaly model",
  "ml.model.activate": "Activated a model version",
  "log.upload": "Uploaded a log file",
  "log.ingest": "Ingested collector logs",
  "export.report": "Exported a report",
  "export.events": "Exported events",
  "export.alerts": "Exported alerts",
  "export.threat_feed": "Exported a threat feed",
});

export function auditActionLabel(action) {
  return ACTION_LABELS[action] || String(action || "Unknown action");
}

function text(value, maxLength) {
  return typeof value === "string" ? value.trim().slice(0, maxLength) : "";
}

export function normalizeAuditEvent(raw) {
  const id = Number(raw?.id);
  if (!Number.isSafeInteger(id) || id <= 0) return null;
  const occurredAt = new Date(raw.occurred_at);
  const detail = raw.detail && typeof raw.detail === "object" && !Array.isArray(raw.detail) ? raw.detail : {};
  return {
    id,
    occurredAt: Number.isNaN(occurredAt.getTime()) ? "" : occurredAt.toISOString(),
    actorName: text(raw.actor_name, 100) || "Anonymous",
    actorRole: text(raw.actor_role, 50),
    action: text(raw.action, 80),
    outcome: raw.outcome === "FAILURE" ? "failure" : "success",
    targetType: text(raw.target_type, 50),
    targetId: text(raw.target_id == null ? "" : String(raw.target_id), 100),
    targetLabel: text(raw.target_label, 255),
    ipAddress: text(raw.ip_address, 64),
    userAgent: text(raw.user_agent, 300),
    detail,
  };
}

function words(key) {
  return String(key).replaceAll("_", " ");
}

function plain(value) {
  if (value === null || value === undefined || value === "") return "none";
  if (typeof value === "boolean") return value ? "yes" : "no";
  if (Array.isArray(value)) return value.map(plain).join(", ") || "none";
  if (typeof value === "object") {
    return Object.entries(value).map(([key, inner]) => `${words(key)} ${plain(inner)}`).join(", ") || "none";
  }
  return String(value);
}

/** One readable line per fact in an event's detail object. */
export function summarizeAuditDetail(detail) {
  if (!detail || typeof detail !== "object") return [];
  const lines = [];
  for (const [key, value] of Object.entries(detail)) {
    if (key === "changes" && value && typeof value === "object") {
      for (const [field, change] of Object.entries(value)) {
        lines.push(`${words(field)}: ${plain(change?.from)} to ${plain(change?.to)}`);
      }
    } else if (key === "from" && "to" in detail) {
      lines.push(`${plain(value)} to ${plain(detail.to)}`);
    } else if (key === "to" && "from" in detail) {
      continue;
    } else {
      lines.push(`${words(key)}: ${plain(value)}`);
    }
  }
  return lines;
}

export function auditTargetLabel(event) {
  if (event.targetLabel) return event.targetLabel;
  if (event.targetId) return `${words(event.targetType || "record")} ${event.targetId}`;
  return "";
}

/** Query string for GET /audit/events from the page's filter state. */
export function auditQueryParams({ category = "", outcome = "", actor = "", beforeId = null, limit = 50 } = {}) {
  const params = new URLSearchParams();
  if (category) params.set("category", category);
  if (outcome) params.set("outcome", outcome.toUpperCase());
  const trimmedActor = actor.trim().slice(0, 100);
  if (trimmedActor) params.set("actor", trimmedActor);
  if (beforeId) params.set("before_id", String(beforeId));
  params.set("limit", String(limit));
  return params.toString();
}

/** Apply the same filters and paging to in-memory events (sample mode). */
export function filterAuditEvents(events, { category = "", outcome = "", actor = "", beforeId = null, limit = 50 } = {}) {
  const needle = actor.trim().toLowerCase();
  const matches = events
    .filter((event) => !category || event.action.startsWith(`${category}.`))
    .filter((event) => !outcome || event.outcome === outcome.toLowerCase())
    .filter((event) => !needle || event.actorName.toLowerCase().includes(needle))
    .filter((event) => !beforeId || event.id < beforeId)
    .sort((a, b) => b.id - a.id);
  const visible = matches.slice(0, limit);
  return {
    events: visible,
    nextBeforeId: matches.length > limit ? visible.at(-1).id : null,
  };
}
