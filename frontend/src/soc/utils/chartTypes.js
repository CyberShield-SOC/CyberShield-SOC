import { useCallback, useState } from "react";

// Chart-type switcher for the dashboard panels. Every adapter here reads the
// series the panel already shows; none of them fetch or filter anything new.

export const CHART_TYPE_LABELS = Object.freeze({
  line: "Line graph",
  stacked: "Stacked bar chart",
  horizontal: "Horizontal bar chart",
  heatmap: "Heatmap matrix",
  donut: "Donut chart",
});

// "Events Over Time" has no per-severity breakdown, so only the two types that
// show its total are offered. Offering stacked or heatmap there would mean
// inventing data.
export const PANEL_CHART_TYPES = Object.freeze({
  events: Object.freeze(["line", "horizontal"]),
  severity: Object.freeze(["donut", "line", "stacked", "horizontal", "heatmap"]),
  volume: Object.freeze(["stacked", "line", "horizontal", "heatmap", "donut"]),
});

// Each panel's default is the chart it drew before the switcher existed.
export const PANEL_DEFAULT_CHART = Object.freeze({
  events: "line",
  severity: "donut",
  volume: "stacked",
});

const STORAGE_PREFIX = "cybershield-chart-type:";

function safeStorage() {
  try {
    return globalThis.localStorage ?? null;
  } catch {
    // Some browsers throw on access when site data is blocked.
    return null;
  }
}

export function readStoredChartType(panelKey, storage = safeStorage()) {
  const allowed = PANEL_CHART_TYPES[panelKey] || [];
  const fallback = PANEL_DEFAULT_CHART[panelKey];
  try {
    const stored = storage?.getItem(STORAGE_PREFIX + panelKey);
    return allowed.includes(stored) ? stored : fallback;
  } catch {
    return fallback;
  }
}

export function writeStoredChartType(panelKey, type, storage = safeStorage()) {
  try {
    storage?.setItem(STORAGE_PREFIX + panelKey, type);
  } catch {
    // Storage is blocked or full: the choice still applies for this page view.
  }
}

// Per-panel state, persisted so the choice survives a refresh.
export function usePanelChartType(panelKey) {
  const [type, setType] = useState(() => readStoredChartType(panelKey));
  const choose = useCallback((next) => {
    if (!PANEL_CHART_TYPES[panelKey]?.includes(next)) return;
    setType(next);
    writeStoredChartType(panelKey, next);
  }, [panelKey]);
  return [type, choose];
}

// Chart labels from buildTimeBuckets contain line breaks for date + time.
export function flatLabel(label) {
  return String(label ?? "").replace(/\s*\n\s*/g, " ").trim();
}

function count(value) {
  const number = Number(value);
  return Number.isFinite(number) && number > 0 ? number : 0;
}

// Events over time: one item per time bucket, in time order.
export function timeTotalItems({ values = [], labels = [] }) {
  return values.map((value, index) => ({
    label: flatLabel(labels[index]),
    value: count(value),
  }));
}

// Alert volume over time: total alerts per bucket across all severities.
export function totalPerBucket(severityBuckets, series) {
  return (Array.isArray(severityBuckets) ? severityBuckets : []).map((bucket) => ({
    // Raw label: the line chart draws its own two-line axis labels.
    label: bucket.label,
    value: series.reduce((sum, item) => sum + count(bucket[item.key]), 0),
  }));
}

// Per-severity totals across the whole range, in the order of `series`.
export function severityTotals(severityBuckets, series) {
  const buckets = Array.isArray(severityBuckets) ? severityBuckets : [];
  return series.map((item) => ({
    key: item.key,
    label: item.label,
    color: item.color,
    value: buckets.reduce((sum, bucket) => sum + count(bucket[item.key]), 0),
  }));
}

// Largest first. Ties keep their original order, so the output is stable.
export function sortByValueDesc(items) {
  return items
    .map((item, index) => ({ item, index }))
    .sort((a, b) => (b.item.value - a.item.value) || (a.index - b.index))
    .map(({ item }) => item);
}

// Heatmap grid: one row per severity (most severe on top), one column per
// time bucket. `max` is the largest cell, which sets the colour scale.
export function severityHeatmap(severityBuckets, series) {
  const buckets = Array.isArray(severityBuckets) ? severityBuckets : [];
  const columns = buckets.map((bucket) => flatLabel(bucket.label));
  const rows = series
    .slice()
    .reverse()
    .map((item) => ({
      key: item.key,
      label: item.label,
      color: item.color,
      cells: buckets.map((bucket) => count(bucket[item.key])),
    }));
  const max = rows.reduce((top, row) => row.cells.reduce((inner, value) => Math.max(inner, value), top), 0);
  return { columns, rows, max };
}
