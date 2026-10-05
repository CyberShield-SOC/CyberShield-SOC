import test from "node:test";
import assert from "node:assert/strict";
import {
  TIMEZONE_OPTIONS,
  conditionTimezonePayload,
  conditionToDsl,
  parseHourRange,
  supportsTimezone,
} from "../src/soc/utils/ruleConditions.js";

const dslText = (condition, type = "timestamp") =>
  conditionToDsl(condition, type).map((fragment) => fragment.text).join("");

test("timezone is only supported on timestamp between conditions", () => {
  assert.equal(supportsTimezone("timestamp", "timestamp", "between"), true);
  assert.equal(supportsTimezone("timestamp", "timestamp", "before"), false);
  assert.equal(supportsTimezone("status", "string", "between"), false);
});

test("payload sends null for UTC and for conditions without a timezone", () => {
  const offHours = { field: "timestamp", operator: "between", value: "00:00 – 06:00", timezone: "" };
  assert.equal(conditionTimezonePayload(offHours, "timestamp"), null);
  assert.equal(conditionTimezonePayload({ ...offHours, timezone: undefined }, "timestamp"), null);
});

test("payload sends the IANA name for a local-time window", () => {
  const offHours = { field: "timestamp", operator: "between", value: "00:00 – 06:00", timezone: "America/Chicago" };
  assert.equal(conditionTimezonePayload(offHours, "timestamp"), "America/Chicago");
});

test("payload drops a stale timezone when the operator no longer supports one", () => {
  const stale = { field: "timestamp", operator: "before", value: "2026-06-14T02:00:00Z", timezone: "America/Chicago" };
  assert.equal(conditionTimezonePayload(stale, "timestamp"), null);
});

test("DSL preview shows the zone for a local-time hour range", () => {
  const condition = { field: "timestamp", operator: "between", value: "00:00 – 06:00", timezone: "America/Chicago" };
  assert.equal(dslText(condition), 'hour(ts, "America/Chicago") in 00..06');
});

test("DSL preview is unchanged for UTC hour ranges", () => {
  const condition = { field: "timestamp", operator: "between", value: "00:00 – 06:00", timezone: "" };
  assert.equal(dslText(condition), "hour(ts) in 00..06");
  assert.equal(dslText({ ...condition, timezone: undefined }), "hour(ts) in 00..06");
});

test("DSL preview for a non-range between value is unchanged by the timezone", () => {
  const condition = { field: "timestamp", operator: "between", value: "2026-06-14", timezone: "America/Chicago" };
  assert.equal(dslText(condition), 'ts between "2026-06-14"');
});

test("parseHourRange accepts en dash, hyphen and loose spacing", () => {
  assert.deepEqual(parseHourRange("00:00 – 06:00"), { from: "00", to: "06" });
  assert.deepEqual(parseHourRange("22:00-6:00"), { from: "22", to: "06" });
  assert.equal(parseHourRange("nonsense"), null);
});

test("timezone options start with UTC and contain no duplicates", () => {
  assert.equal(TIMEZONE_OPTIONS[0].value, "");
  const values = TIMEZONE_OPTIONS.map((option) => option.value);
  assert.equal(new Set(values).size, values.length);
});

test("every picker zone is a valid IANA name", () => {
  for (const option of TIMEZONE_OPTIONS) {
    if (!option.value) continue;
    // Throws RangeError for names the runtime does not know.
    assert.doesNotThrow(() => new Intl.DateTimeFormat("en-US", { timeZone: option.value }), option.value);
  }
});
