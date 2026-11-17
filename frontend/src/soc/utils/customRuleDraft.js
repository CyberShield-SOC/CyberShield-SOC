import { FIELD_CATALOG, GROUP_OPTIONS, OPERATORS_BY_TYPE, SEVERITY_OPTIONS, WINDOW_SECONDS_BY_VALUE } from "../data/ruleBuilderMockData.js";
import { RULE_CATEGORIES } from "../data/ruleCategories.js";
import { splitAlternatives, supportsAlternatives } from "./ruleConditions.js";

const CUSTOM_WINDOW = /^(\d+)s$/;
const TECHNIQUE = /^T\d{4}(\.\d{3})?$/;
export const MAX_MIN_COUNT = 10000;

/** Seconds for a window choice: a preset ("10m") or an imported "120s". */
export function windowSecondsOf(windowValue) {
  if (WINDOW_SECONDS_BY_VALUE[windowValue]) return WINDOW_SECONDS_BY_VALUE[windowValue];
  const match = CUSTOM_WINDOW.exec(String(windowValue || ""));
  const seconds = match ? Number(match[1]) : NaN;
  return seconds >= 60 && seconds <= 86400 ? seconds : null;
}

/** The window choice for stored seconds: its preset, or "<n>s". */
export function windowValueOf(seconds) {
  const preset = Object.keys(WINDOW_SECONDS_BY_VALUE).find((value) => WINDOW_SECONDS_BY_VALUE[value] === Number(seconds));
  return preset || `${Number(seconds)}s`;
}

export function formatWindowSeconds(seconds) {
  const value = Number(seconds);
  if (value % 3600 === 0) return `${value / 3600} hour${value === 3600 ? "" : "s"}`;
  if (value % 60 === 0) return `${value / 60} minute${value === 60 ? "" : "s"}`;
  return `${value} seconds`;
}

const FIELD_TYPES = Object.fromEntries(FIELD_CATALOG.map(({ value, type }) => [value, type]));

export function actionIsEnabled(value) {
  return typeof value === "object" && value !== null ? value.enabled !== false : value === true;
}

export function toggleRuleAction(value, enabled) {
  return typeof value === "object" && value !== null ? { ...value, enabled } : enabled;
}

export function validateCustomRuleDraft({ conditions, groupBy, ruleName, severity, window: windowValue, category, minCount = 1, mitreTechnique = "" }) {
  const problems = [];
  if (!ruleName.trim() || ruleName.trim().length > 120) problems.push("Rule name must contain 1–120 characters");
  if (!RULE_CATEGORIES.some(({ value }) => value === category)) problems.push("Choose a supported category");
  if (!SEVERITY_OPTIONS.some(({ value }) => value === severity)) problems.push("Choose a supported severity");
  if (!GROUP_OPTIONS.some(({ value }) => value === groupBy)) problems.push("Choose a supported grouping");
  if (!windowSecondsOf(windowValue)) problems.push("Choose a supported time window");
  const count = Number(minCount);
  if (!Number.isInteger(count) || count < 1 || count > MAX_MIN_COUNT) problems.push(`Minimum events must be a whole number from 1 to ${MAX_MIN_COUNT.toLocaleString("en-US")}`);
  if (String(mitreTechnique || "").trim() && !TECHNIQUE.test(String(mitreTechnique).trim().toUpperCase())) problems.push("ATT&CK technique must look like T1110 or T1110.001");
  if (!conditions.length || conditions.length > 10) problems.push("Use between 1 and 10 conditions");
  const unknownFields = conditions.filter(({ field }) => !FIELD_TYPES[field]).map(({ field }) => field || "(empty)");
  conditions.forEach((condition, index) => {
    const type = FIELD_TYPES[condition.field];
    if (!type) return;
    const label = `Condition ${index + 1}`;
    const value = String(condition.value ?? "").trim();
    const alternatives = supportsAlternatives(type, condition.operator) ? splitAlternatives(value) : [value];
    if (!OPERATORS_BY_TYPE[type].includes(condition.operator)) problems.push(`${label} has an invalid operator`);
    if (!value) problems.push(`${label} needs a value`);
    else if (alternatives.length > 1 && alternatives.some((item) => !item)) problems.push(`${label} has an empty alternative between | separators`);
    else if (alternatives.length > 50) problems.push(`${label} lists more than 50 alternatives`);
    else if (alternatives.some((item) => item.length > 200)) problems.push(`${label} has a value longer than 200 characters`);
    else if (condition.operator === "in" && value.split(",").some((item) => !item.trim())) problems.push(`${label} contains an empty list item`);
    else if (type === "number") {
      const ports = condition.operator === "in" ? value.split(",") : alternatives;
      if (ports.some((port) => !/^\d+$/.test(port.trim()) || Number(port) > 65535)) problems.push(`${label} needs port numbers from 0 to 65535`);
    } else if (type === "timestamp") {
      if (condition.operator === "between") {
        const match = value.match(/^(\d{1,2}):(\d{2})\s*[-–]\s*(\d{1,2}):(\d{2})$/);
        if (!match || Number(match[1]) > 23 || Number(match[3]) > 23 || Number(match[2]) > 59 || Number(match[4]) > 59 || Number(match[1]) * 60 + Number(match[2]) === Number(match[3]) * 60 + Number(match[4])) {
          problems.push(`${label} needs a nonempty HH:MM – HH:MM range`);
        }
        try { new Intl.DateTimeFormat("en", { timeZone: condition.timezone || "UTC" }); }
        catch { problems.push(`${label} needs a valid timezone`); }
      } else if (!Number.isFinite(Date.parse(value))) problems.push(`${label} needs a valid timestamp`);
    }
  });
  return { syntaxProblems: problems, unknownFields };
}

/** Only supplied fields are sent, so a status change cannot reset the rule. */
export function customRuleUpdates(updates) {
  const body = {};
  const fields = { name: "name", category: "category", severity: "severity", tactic: "tactic", conditions: "conditions", groupBy: "group_by", windowSeconds: "window_seconds", minCount: "min_count", mitreTechnique: "mitre_technique", actions: "actions", dsl: "dsl" };
  for (const [key, apiKey] of Object.entries(fields)) {
    if (!Object.hasOwn(updates, key) || updates[key] === undefined) continue;
    const value = updates[key];
    if (key === "severity" && typeof value === "string") body[apiKey] = value.toUpperCase();
    else if (key === "tactic") body[apiKey] = value || null;
    else if (key === "mitreTechnique") body[apiKey] = String(value || "").trim().toUpperCase() || null;
    else if (key === "minCount") body[apiKey] = Number(value) || 1;
    else body[apiKey] = value;
  }
  if (Object.hasOwn(updates, "status") && updates.status !== undefined) body.status = String(updates.status).toUpperCase();
  return body;
}
