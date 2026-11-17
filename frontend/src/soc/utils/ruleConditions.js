/**
 * Pure helpers for Rule Builder conditions: the timezone choices for
 * hour-range conditions, the payload value sent to the backend, and the DSL
 * preview fragments. Kept free of React and CSS so they can be tested with
 * node --test (see tests/ruleConditions.test.js).
 */

/**
 * Zones offered for hour-range ("between") timestamp conditions. The empty
 * value means UTC, which is what conditions saved before this option used.
 * The backend accepts any IANA name; this list is the curated set shown in
 * the picker.
 */
export const TIMEZONE_OPTIONS = Object.freeze([
  { value: "", label: "UTC (default)" },
  { value: "America/New_York", label: "America/New_York" },
  { value: "America/Chicago", label: "America/Chicago" },
  { value: "America/Denver", label: "America/Denver" },
  { value: "America/Los_Angeles", label: "America/Los_Angeles" },
  { value: "America/Phoenix", label: "America/Phoenix" },
  { value: "America/Anchorage", label: "America/Anchorage" },
  { value: "Pacific/Honolulu", label: "Pacific/Honolulu" },
  { value: "America/Sao_Paulo", label: "America/Sao_Paulo" },
  { value: "Europe/London", label: "Europe/London" },
  { value: "Europe/Paris", label: "Europe/Paris" },
  { value: "Europe/Berlin", label: "Europe/Berlin" },
  { value: "Africa/Johannesburg", label: "Africa/Johannesburg" },
  { value: "Asia/Dubai", label: "Asia/Dubai" },
  { value: "Asia/Kolkata", label: "Asia/Kolkata" },
  { value: "Asia/Singapore", label: "Asia/Singapore" },
  { value: "Asia/Tokyo", label: "Asia/Tokyo" },
  { value: "Australia/Sydney", label: "Australia/Sydney" },
]);

/**
 * "Any of" lists. A string condition (other than "in", which keeps its
 * comma list) and a port "equals" may hold several alternatives, written
 * with | between them: `/bin/bash | /bin/sh`. A literal pipe is \|.
 */
export function supportsAlternatives(type, operator) {
  if (type === "string") return operator !== "in";
  return type === "number" && operator === "equals";
}

export function splitAlternatives(text) {
  const parts = [];
  let current = "";
  const source = String(text ?? "");
  for (let index = 0; index < source.length; index += 1) {
    const char = source[index];
    if (char === "\\" && source[index + 1] === "|") {
      current += "|";
      index += 1;
    } else if (char === "|") {
      parts.push(current.trim());
      current = "";
    } else {
      current += char;
    }
  }
  parts.push(current.trim());
  return parts;
}

export function joinAlternatives(values) {
  return (values || []).map((value) => String(value).replace(/\|/g, "\\|")).join(" | ");
}

/** A stored/API condition as the builder edits it: one text value plus NOT. */
export function conditionFromApi(condition) {
  return {
    field: condition.field,
    operator: condition.operator,
    value: Array.isArray(condition.values) ? joinAlternatives(condition.values) : String(condition.value ?? ""),
    negate: condition.negate === true,
    timezone: condition.timezone ?? "",
  };
}

/** The builder's condition as the API expects it. */
export function conditionToApi(condition, type) {
  const payload = {
    field: condition.field,
    operator: condition.operator,
    timezone: conditionTimezonePayload(condition, type),
  };
  const alternatives = supportsAlternatives(type, condition.operator)
    ? splitAlternatives(condition.value)
    : [String(condition.value ?? "")];
  if (alternatives.length > 1) payload.values = alternatives;
  else payload.value = alternatives[0];
  if (condition.negate) payload.negate = true;
  return payload;
}

/** One line for rule summaries: `NOT command endswith /bin/bash | /bin/sh`. */
export function describeCondition(condition) {
  const value = Array.isArray(condition.values) ? condition.values.join(" | ") : condition.value;
  return `${condition.negate ? "NOT " : ""}${condition.field} ${condition.operator} ${value}`;
}

/** Whether a condition can carry a timezone: only timestamp "between" rows. */
export function supportsTimezone(field, type, operator) {
  return field === "timestamp" && type === "timestamp" && operator === "between";
}

/** Timezone value for the API: an IANA name, or null for UTC (the default). */
export function conditionTimezonePayload(condition, type) {
  if (!supportsTimezone(condition.field, type, condition.operator)) return null;
  return condition.timezone || null;
}

/** "00:00 – 06:00" (also accepts "-"/"–" with loose spacing) -> { from: "00", to: "06" } */
export function parseHourRange(value) {
  const match = String(value || "").match(/^\s*(\d{1,2}):\d{2}\s*[–-]\s*(\d{1,2}):\d{2}\s*$/);
  if (!match) return null;
  return { from: match[1].padStart(2, "0"), to: match[2].padStart(2, "0") };
}

/**
 * Turns one condition into DSL fragments: [{ text, kind }].
 * Kinds map to syntax-highlight classes: field, op, value, fn, punct.
 * `type` is the field's type ("string" | "number" | "timestamp").
 */
export function conditionToDsl(condition, type) {
  const fragments = conditionToDslPositive(condition, type);
  return condition.negate ? [{ text: "not ", kind: "op" }, ...fragments] : fragments;
}

function conditionToDslPositive(condition, type) {
  const value = String(condition.value || "").trim();
  const field = { text: condition.field, kind: "field" };
  const alternatives = supportsAlternatives(type, condition.operator) ? splitAlternatives(value) : [value];
  if (alternatives.length > 1) {
    const list = { text: `[${alternatives.map((item) => (type === "number" ? item : `"${item}"`)).join(", ")}]`, kind: "value" };
    if (condition.operator === "equals" || condition.operator === "not equals") {
      return [field, { text: condition.operator === "equals" ? " in " : " not in ", kind: "op" }, list];
    }
    return [
      { text: `any_${condition.operator}(`, kind: "fn" }, field, { text: ", ", kind: "punct" },
      list, { text: ")", kind: "fn" },
    ];
  }

  if (type === "number") {
    const compact = { text: value.replace(/\s+/g, ""), kind: "value" };
    if (condition.operator === "sum >" || condition.operator === "avg >") {
      const fn = condition.operator === "sum >" ? "sum" : "avg";
      return [
        { text: `${fn}(`, kind: "fn" }, field, { text: ")", kind: "fn" },
        { text: " > ", kind: "op" }, compact,
      ];
    }
    return [field, { text: ` ${condition.operator} `, kind: "op" }, compact];
  }

  if (type === "timestamp") {
    if (condition.operator === "between") {
      const range = parseHourRange(value);
      if (range) {
        const times = value.match(/\d{1,2}:\d{2}/g).map((time) => time.padStart(5, "0"));
        return [
          { text: "time_range(", kind: "fn" }, { text: "ts", kind: "field" },
          { text: ", ", kind: "punct" }, { text: `"${times[0]}"`, kind: "value" },
          { text: ", ", kind: "punct" }, { text: `"${times[1]}"`, kind: "value" },
          { text: ", ", kind: "punct" }, { text: `"${condition.timezone || "UTC"}"`, kind: "value" },
          { text: ", end_exclusive: true)", kind: "punct" },
        ];
      }
      return [
        { text: "ts", kind: "field" }, { text: " between ", kind: "op" },
        { text: `"${value}"`, kind: "value" },
      ];
    }
    const symbol = condition.operator === "before" ? "<" : ">";
    return [{ text: "ts", kind: "field" }, { text: ` ${symbol} `, kind: "op" }, { text: `"${value}"`, kind: "value" }];
  }

  if (["contains", "startswith", "endswith"].includes(condition.operator)) {
    return [
      { text: `${condition.operator}(`, kind: "fn" }, field, { text: ", ", kind: "punct" },
      { text: `"${value}"`, kind: "value" }, { text: ")", kind: "fn" },
    ];
  }
  if (condition.operator === "in") {
    const items = value.split(",").map((item) => `"${item.trim()}"`).join(", ");
    return [field, { text: " in ", kind: "op" }, { text: `(${items})`, kind: "value" }];
  }
  const symbol = condition.operator === "not equals" ? "!=" : "==";
  return [field, { text: ` ${symbol} `, kind: "op" }, { text: `"${value}"`, kind: "value" }];
}
