/**
 * Built-in detection rule configuration helpers: which settings a rule
 * accepts (the backend reports them as `tunables`), turning a rule's live
 * config into an editable draft and back into a PATCH body, and formatting
 * alert evidence. Pure functions — covered by tests/ruleConfig.test.js.
 */

export const CONFIG_FIELDS = Object.freeze([
  { key: "threshold", apiKey: "threshold", label: "Threshold (count)", kind: "number", min: 1, max: 10000 },
  { key: "failThreshold", apiKey: "fail_threshold", label: "Failure threshold (count)", kind: "number", min: 1, max: 10000 },
  { key: "windowSeconds", apiKey: "window_seconds", label: "Window (seconds)", kind: "number", min: 1, max: 86400 },
  { key: "successWindowSeconds", apiKey: "success_window_seconds", label: "Success window (seconds)", kind: "number", min: 1, max: 86400 },
  { key: "cooldownSeconds", apiKey: "cooldown_seconds", label: "Cooldown (seconds)", kind: "number", min: 0, max: 86400, optional: true },
  { key: "confidence", apiKey: "confidence", label: "Confidence (0–100)", kind: "number", min: 0, max: 100, optional: true },
  { key: "startHour", apiKey: "start_hour", label: "Business hours start (UTC hour)", kind: "number", min: 0, max: 23 },
  { key: "endHour", apiKey: "end_hour", label: "Business hours end (UTC hour)", kind: "number", min: 0, max: 23 },
  { key: "allowlist", apiKey: "allowlist", label: "Allowlist (one per line)", kind: "list" },
]);

const FIELD_BY_KEY = Object.freeze(Object.fromEntries(CONFIG_FIELDS.map((field) => [field.key, field])));
const MAX_ALLOWLIST = 500;

/** Settings the rule actually reads, in display order. */
export function editableFields(live) {
  const tunables = new Set(live?.tunables || []);
  return CONFIG_FIELDS.filter((field) => tunables.has(field.apiKey));
}

export function parseAllowlist(text) {
  return [...new Set(
    String(text || "")
      .split(/[\n,]/)
      .map((item) => item.trim())
      .filter(Boolean),
  )];
}

export function draftFromLive(live) {
  const values = {};
  for (const field of editableFields(live)) {
    const current = live[field.key];
    values[field.key] = field.kind === "list"
      ? (Array.isArray(current) ? current.join("\n") : "")
      : (current === null || current === undefined ? "" : String(current));
  }
  const params = {};
  for (const [key, fallback] of Object.entries(live?.defaultParams || {})) {
    const current = live?.params?.[key] ?? fallback;
    params[key] = String(current);
  }
  return { engineKey: live?.engineKey, values, params };
}

function sameList(left, right) {
  const a = Array.isArray(left) ? left : [];
  const b = Array.isArray(right) ? right : [];
  return a.length === b.length && a.every((item, index) => item === b[index]);
}

/**
 * Validate a draft and return only what changed, keyed like the repository
 * update methods expect (camelCase; params as an object).
 */
export function updatesFromDraft(draft, live) {
  const errors = {};
  const updates = {};

  for (const field of editableFields(live)) {
    const raw = draft?.values?.[field.key];
    if (field.kind === "list") {
      const list = parseAllowlist(raw);
      if (list.length > MAX_ALLOWLIST) errors[field.key] = `At most ${MAX_ALLOWLIST} entries.`;
      else if (list.some((item) => item.length > 255)) errors[field.key] = "Entries must be 255 characters or fewer.";
      else if (!sameList(list, live[field.key])) updates[field.key] = list;
      continue;
    }

    const text = String(raw ?? "").trim();
    if (text === "") {
      if (!field.optional && live[field.key] !== null && live[field.key] !== undefined) {
        errors[field.key] = "Required.";
      }
      continue;
    }
    const number = Number(text);
    if (!Number.isInteger(number) || number < field.min || number > field.max) {
      errors[field.key] = `Enter a whole number from ${field.min} to ${field.max}.`;
      continue;
    }
    if (number !== live[field.key]) updates[field.key] = number;
  }

  const paramUpdates = {};
  for (const [key, fallback] of Object.entries(live?.defaultParams || {})) {
    const text = String(draft?.params?.[key] ?? "").trim();
    const current = live?.params?.[key] ?? fallback;
    let value;
    if (typeof fallback === "number") {
      value = Number(text);
      if (text === "" || !Number.isFinite(value) || value < 0) {
        errors[`params.${key}`] = "Enter a non-negative number.";
        continue;
      }
    } else if (typeof fallback === "boolean") {
      value = ["true", "1", "yes", "on"].includes(text.toLowerCase());
    } else {
      value = text;
    }
    if (value !== current) paramUpdates[key] = value;
  }
  if (Object.keys(paramUpdates).length) updates.params = paramUpdates;

  return { errors, updates };
}

/** camelCase repository updates -> backend PATCH body. */
export function detectionRuleApiBody(updates = {}) {
  const body = {};
  if (typeof updates.enabled === "boolean") body.enabled = updates.enabled;
  for (const field of CONFIG_FIELDS) {
    if (!(field.key in updates) || updates[field.key] === undefined) continue;
    const value = updates[field.key];
    if (field.kind === "list") body[field.apiKey] = Array.isArray(value) ? value.map(String) : parseAllowlist(value);
    else if (value !== null && value !== "") body[field.apiKey] = Number(value);
  }
  if (updates.params && typeof updates.params === "object") body.params = { ...updates.params };
  return body;
}

export function humanizeKey(key) {
  const text = String(key || "").replaceAll("_", " ").replaceAll(".", " · ");
  return text.charAt(0).toUpperCase() + text.slice(1);
}

function formatScalar(key, value) {
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (typeof value === "number" && /bytes/i.test(key) && value >= 1_000_000) {
    return `${(value / 1_000_000).toFixed(1)} MB`;
  }
  if (typeof value === "number" && /seconds$/i.test(key) && value >= 120) {
    return `${Math.round(value / 60)} min`;
  }
  return String(value);
}

/** Short human summary of a rule's active configuration. */
export function describeLiveConfig(live) {
  if (!live) return "";
  const parts = [live.enabled === false ? "Disabled" : "Enabled"];
  for (const field of editableFields(live)) {
    const value = live[field.key];
    if (field.kind === "list") {
      parts.push(`${field.label.split(" (")[0]}: ${Array.isArray(value) && value.length ? value.join(", ") : "none"}`);
    } else if (value !== null && value !== undefined) {
      parts.push(`${field.label.split(" (")[0]}: ${value}`);
    }
  }
  for (const [key, fallback] of Object.entries(live.defaultParams || {})) {
    parts.push(`${humanizeKey(key)}: ${live.params?.[key] ?? fallback}`);
  }
  return parts.join(" · ");
}

/** Alert evidence as display rows; empty values dropped, nested values flattened. */
export function evidenceEntries(evidence) {
  if (!evidence || typeof evidence !== "object" || Array.isArray(evidence)) return [];
  const rows = [];
  for (const [key, value] of Object.entries(evidence)) {
    if (value === null || value === undefined || value === "" || key === "prefix") continue;
    if (Array.isArray(value)) {
      if (!value.length) continue;
      const items = value.map((item) => {
        if (item && typeof item === "object") {
          return Object.entries(item)
            .filter(([, inner]) => inner !== null && inner !== undefined && inner !== "")
            .map(([innerKey, inner]) => `${humanizeKey(innerKey)}: ${formatScalar(innerKey, inner)}`)
            .join(", ");
        }
        return String(item);
      });
      rows.push({ key, label: humanizeKey(key), value: items.join(key === "reasons" || key === "findings" ? " | " : ", ") });
    } else if (typeof value === "object") {
      const inner = Object.entries(value).map(([innerKey, innerValue]) => `${innerKey} ${innerValue}`).join(", ");
      if (inner) rows.push({ key, label: humanizeKey(key), value: inner });
    } else {
      rows.push({ key, label: humanizeKey(key), value: formatScalar(key, value) });
    }
  }
  return rows;
}

export function fieldLabel(key) {
  return FIELD_BY_KEY[key]?.label || humanizeKey(key);
}

export const ENTITY_LABELS = Object.freeze({ source_ip: "Source IP", account: "Account", host: "Host" });
