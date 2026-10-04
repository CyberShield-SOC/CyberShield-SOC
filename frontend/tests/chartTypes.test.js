import test from "node:test";
import assert from "node:assert/strict";
import {
  PANEL_CHART_TYPES,
  PANEL_DEFAULT_CHART,
  flatLabel,
  readStoredChartType,
  severityHeatmap,
  severityTotals,
  sortByValueDesc,
  timeTotalItems,
  totalPerBucket,
  writeStoredChartType,
} from "../src/soc/utils/chartTypes.js";

const SERIES = [
  { key: "low", label: "Low", color: "low-color" },
  { key: "medium", label: "Medium", color: "medium-color" },
  { key: "high", label: "High", color: "high-color" },
  { key: "critical", label: "Critical", color: "critical-color" },
];

const BUCKETS = [
  { label: "Oct 4\n9 AM", low: 1, medium: 2, high: 0, critical: 3 },
  { label: "Oct 4\n10 AM", low: 0, medium: 0, high: 4, critical: 0 },
  { label: "Oct 4\n11 AM", low: 5, medium: 0, high: 1, critical: 2 },
];

class MemoryStorage {
  constructor() { this.map = new Map(); }
  getItem(key) { return this.map.has(key) ? this.map.get(key) : null; }
  setItem(key, value) { this.map.set(key, String(value)); }
}

test("every panel offers its default chart type", () => {
  for (const panel of Object.keys(PANEL_DEFAULT_CHART)) {
    assert.ok(PANEL_CHART_TYPES[panel].includes(PANEL_DEFAULT_CHART[panel]), panel);
  }
  assert.equal(PANEL_DEFAULT_CHART.events, "line");
  assert.equal(PANEL_DEFAULT_CHART.severity, "donut");
  assert.equal(PANEL_DEFAULT_CHART.volume, "stacked");
});

test("events panel only offers types that can show a plain total", () => {
  assert.deepEqual([...PANEL_CHART_TYPES.events], ["line", "horizontal"]);
});

test("flatLabel joins a two-line bucket label with a space", () => {
  assert.equal(flatLabel("Oct 4\n9 AM"), "Oct 4 9 AM");
  assert.equal(flatLabel(undefined), "");
});

test("timeTotalItems keeps time order and sanitises counts", () => {
  const items = timeTotalItems({ values: [3, -2, Number.NaN, 7], labels: ["a\nb", "c", "d", "e"] });
  assert.deepEqual(items, [
    { label: "a b", value: 3 },
    { label: "c", value: 0 },
    { label: "d", value: 0 },
    { label: "e", value: 7 },
  ]);
});

test("totalPerBucket sums every severity in each bucket and keeps the raw label", () => {
  const totals = totalPerBucket(BUCKETS, SERIES);
  assert.deepEqual(totals.map((bucket) => bucket.value), [6, 4, 8]);
  assert.equal(totals[0].label, "Oct 4\n9 AM");
});

test("severityTotals sums each severity across the whole range", () => {
  const totals = severityTotals(BUCKETS, SERIES);
  assert.deepEqual(totals.map((item) => [item.key, item.value]), [
    ["low", 6],
    ["medium", 2],
    ["high", 5],
    ["critical", 5],
  ]);
  const grand = totals.reduce((sum, item) => sum + item.value, 0);
  assert.equal(grand, BUCKETS.reduce((sum, bucket) => sum + bucket.low + bucket.medium + bucket.high + bucket.critical, 0));
});

test("sortByValueDesc orders largest first and keeps ties in original order", () => {
  const sorted = sortByValueDesc([
    { label: "a", value: 2 },
    { label: "b", value: 9 },
    { label: "c", value: 2 },
    { label: "d", value: 0 },
  ]);
  assert.deepEqual(sorted.map((item) => item.label), ["b", "a", "c", "d"]);
});

test("severityHeatmap puts the most severe row first and finds the largest cell", () => {
  const grid = severityHeatmap(BUCKETS, SERIES);
  assert.deepEqual(grid.rows.map((row) => row.key), ["critical", "high", "medium", "low"]);
  assert.deepEqual(grid.columns, ["Oct 4 9 AM", "Oct 4 10 AM", "Oct 4 11 AM"]);
  assert.deepEqual(grid.rows[0].cells, [3, 0, 2]);
  assert.equal(grid.max, 5);
});

test("severityHeatmap handles empty input without throwing", () => {
  const grid = severityHeatmap([], SERIES);
  assert.equal(grid.max, 0);
  assert.deepEqual(grid.columns, []);
});

test("readStoredChartType returns the stored choice when it is allowed for the panel", () => {
  const storage = new MemoryStorage();
  writeStoredChartType("volume", "heatmap", storage);
  assert.equal(readStoredChartType("volume", storage), "heatmap");
});

test("readStoredChartType falls back to the default for unknown or disallowed values", () => {
  const storage = new MemoryStorage();
  storage.setItem("cybershield-chart-type:events", "heatmap");
  storage.setItem("cybershield-chart-type:severity", "pie");
  assert.equal(readStoredChartType("events", storage), "line");
  assert.equal(readStoredChartType("severity", storage), "donut");
  assert.equal(readStoredChartType("volume", storage), "stacked");
});

test("storage that throws or is missing falls back to the defaults without throwing", () => {
  const throwing = {
    getItem() { throw new Error("blocked"); },
    setItem() { throw new Error("blocked"); },
  };
  assert.equal(readStoredChartType("severity", throwing), "donut");
  assert.doesNotThrow(() => writeStoredChartType("severity", "line", throwing));
  assert.equal(readStoredChartType("severity", null), "donut");
  assert.doesNotThrow(() => writeStoredChartType("severity", "line", null));
});

test("each panel's selection is stored independently", () => {
  const storage = new MemoryStorage();
  writeStoredChartType("severity", "heatmap", storage);
  assert.equal(readStoredChartType("severity", storage), "heatmap");
  assert.equal(readStoredChartType("volume", storage), "stacked");
  assert.equal(readStoredChartType("events", storage), "line");
});
