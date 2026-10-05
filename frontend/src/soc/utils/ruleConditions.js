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
  const value = String(condition.value || "").trim();
  const field = { text: condition.field, kind: "field" };

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
        const zone = condition.timezone
          ? [{ text: ", ", kind: "punct" }, { text: `"${condition.timezone}"`, kind: "value" }]
          : [];
        return [
          { text: "hour(", kind: "fn" }, { text: "ts", kind: "field" }, ...zone, { text: ")", kind: "fn" },
          { text: " in ", kind: "op" }, { text: `${range.from}..${range.to}`, kind: "value" },
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

  if (condition.operator === "contains") {
    return [
      { text: "contains(", kind: "fn" }, field, { text: ", ", kind: "punct" },
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
