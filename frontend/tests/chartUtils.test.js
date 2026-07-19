import test from "node:test";
import assert from "node:assert/strict";
import {
  buildLineChartModel,
  buildStackedBarModel,
  buildVisibleTickIndexes,
  formatChartPercentage,
} from "../src/soc/utils/chartUtils.js";

test("builds a readable rounded count scale for large chart values", () => {
  const model = buildLineChartModel([18000, 25000, 20000, 26000, 21000, 29500, 22000, 32842]);
  assert.equal(model.axisMax, 40000);
  assert.deepEqual(model.ticks.map((tick) => tick.value), [40000, 30000, 20000, 10000, 0]);
  assert.equal(model.points[0].x, 46);
  assert.equal(model.points.at(-1).x, 680);
});

test("clamps malformed and negative chart counts without distorting the baseline", () => {
  const model = buildLineChartModel([Number.NaN, -4, Number.POSITIVE_INFINITY, 3]);
  assert.deepEqual(model.values, [0, 0, 0, 3]);
  assert.deepEqual(model.ticks.map((tick) => tick.value), [3, 2, 1, 0]);
  assert.equal(model.points[0].y, model.baseline);
  assert.equal(model.points[1].y, model.baseline);
});

test("handles empty, zero-only, and single-point chart inputs", () => {
  assert.deepEqual(buildLineChartModel(null).points, []);
  const zeroSeries = buildLineChartModel([0, 0, 0]);
  assert.deepEqual(zeroSeries.ticks.map((tick) => tick.value), [0]);
  assert.ok(zeroSeries.points.every((point) => point.y === zeroSeries.baseline));

  const singlePoint = buildLineChartModel([7]);
  assert.equal(singlePoint.points[0].x, 363);
  assert.ok(singlePoint.points[0].y >= 20 && singlePoint.points[0].y < singlePoint.baseline);
});

test("selects evenly distributed responsive X-axis labels", () => {
  assert.deepEqual(buildVisibleTickIndexes(0, 5), []);
  assert.deepEqual(buildVisibleTickIndexes(3, 5), [0, 1, 2]);
  assert.deepEqual(buildVisibleTickIndexes(12, 5), [0, 3, 6, 8, 11]);
  assert.deepEqual(buildVisibleTickIndexes(24, 3), [0, 12, 23]);
});

test("builds bounded stacked bars from sparse and malformed severity counts", () => {
  const model = buildStackedBarModel([
    { label: "First", low: 1, medium: 2, high: 3, critical: 4 },
    { label: "Second", low: Number.NaN, medium: -2, high: Number.POSITIVE_INFINITY },
  ], ["low", "medium", "high", "critical"], { width: 500 });

  assert.equal(model.total, 10);
  assert.equal(model.axisMax, 10);
  assert.equal(model.bars.length, 2);
  assert.equal(model.bars[0].total, 10);
  assert.equal(model.bars[1].total, 0);
  assert.ok(model.bars.every((bar) => bar.x >= 46 && bar.x + bar.width <= 480));
  assert.ok(model.bars[0].segments.every((segment) => segment.height >= 0));
});

test("handles empty, zero-only, and single-bucket stacked charts", () => {
  assert.deepEqual(buildStackedBarModel(null, ["critical"]).bars, []);
  const zeroOnly = buildStackedBarModel([{ label: "Empty", critical: 0 }], ["critical"]);
  assert.equal(zeroOnly.total, 0);
  assert.deepEqual(zeroOnly.ticks.map((tick) => tick.value), [0]);

  const single = buildStackedBarModel([{ label: "Only", critical: 7 }], ["critical"]);
  assert.equal(single.bars.length, 1);
  assert.ok(single.bars[0].x > 300 && single.bars[0].x < 400);
});

test("formats donut percentages without divide-by-zero or invisible tiny slices", () => {
  assert.equal(formatChartPercentage(0, 0), "0%");
  assert.equal(formatChartPercentage(-2, 10), "0%");
  assert.equal(formatChartPercentage(1, 2000), "<0.1%");
  assert.equal(formatChartPercentage(1, 4), "25.0%");
  assert.equal(formatChartPercentage(4, 4), "100%");
  assert.equal(formatChartPercentage(8, 4), "100%");
});
