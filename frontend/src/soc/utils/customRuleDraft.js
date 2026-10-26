import { FIELD_CATALOG, GROUP_OPTIONS, OPERATORS_BY_TYPE, SEVERITY_OPTIONS, WINDOW_SECONDS_BY_VALUE } from "../data/ruleBuilderMockData.js";
import { RULE_CATEGORIES } from "../data/ruleCategories.js";

const FIELD_TYPES = Object.fromEntries(FIELD_CATALOG.map(({ value, type }) => [value, type]));

export function actionIsEnabled(value) {
  return typeof value === "object" && value !== null ? value.enabled !== false : value === true;
}

export function toggleRuleAction(value, enabled) {
  return typeof value === "object" && value !== null ? { ...value, enabled } : enabled;
}

export function validateCustomRuleDraft({ conditions, groupBy, ruleName, severity, window: windowValue, category }) {
  const problems = [];
  if (!ruleName.trim() || ruleName.trim().length > 120) problems.push("Rule name must contain 1–120 characters");
  if (!RULE_CATEGORIES.some(({ value }) => value === category)) problems.push("Choose a supported category");
  if (!SEVERITY_OPTIONS.some(({ value }) => value === severity)) problems.push("Choose a supported severity");
  if (!GROUP_OPTIONS.some(({ value }) => value === groupBy)) problems.push("Choose a supported grouping");
  if (!WINDOW_SECONDS_BY_VALUE[windowValue]) problems.push("Choose a supported time window");
  if (!conditions.length || conditions.length > 10) problems.push("Use between 1 and 10 conditions");
  const unknownFields = conditions.filter(({ field }) => !FIELD_TYPES[field]).map(({ field }) => field || "(empty)");
  conditions.forEach((condition, index) => {
    const type = FIELD_TYPES[condition.field];
    if (!type) return;
    const label = `Condition ${index + 1}`;
    const value = String(condition.value ?? "").trim();
    if (!OPERATORS_BY_TYPE[type].includes(condition.operator)) problems.push(`${label} has an invalid operator`);
    if (!value) problems.push(`${label} needs a value`);
    else if (condition.operator === "in" && value.split(",").some((item) => !item.trim())) problems.push(`${label} contains an empty list item`);
    else if (type === "number") {
      const ports = condition.operator === "in" ? value.split(",") : [value];
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
  const fields = { name: "name", category: "category", severity: "severity", tactic: "tactic", conditions: "conditions", groupBy: "group_by", windowSeconds: "window_seconds", actions: "actions", dsl: "dsl" };
  for (const [key, apiKey] of Object.entries(fields)) {
    if (!Object.hasOwn(updates, key) || updates[key] === undefined) continue;
    body[apiKey] = key === "severity" && typeof updates[key] === "string" ? updates[key].toUpperCase() : key === "tactic" ? updates[key] || null : updates[key];
  }
  if (Object.hasOwn(updates, "status") && updates.status !== undefined) body.status = String(updates.status).toUpperCase();
  return body;
}
