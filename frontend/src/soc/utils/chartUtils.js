const DEFAULT_PLOT = Object.freeze({ bottom: 28, left: 46, right: 20, top: 20 });

function safeCount(value) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? Math.max(0, parsed) : 0;
}

function niceCeiling(value) {
  if (!Number.isFinite(value) || value <= 0) return 1;
  const magnitude = 10 ** Math.floor(Math.log10(value));
  const fraction = value / magnitude;
  const niceFraction = fraction <= 1 ? 1 : fraction <= 2 ? 2 : fraction <= 5 ? 5 : 10;
  return niceFraction * magnitude;
}

/**
 * Builds geometry and a rounded count scale for the lightweight SVG timeline.
 * Keeping this pure makes backend anomalies testable without rendering React.
 */
export function buildLineChartModel(values, {
  height = 210,
  plot = DEFAULT_PLOT,
  targetIntervals = 4,
  width = 700,
} = {}) {
  const normalized = Array.isArray(values) ? values.map(safeCount) : [];
  if (!normalized.length) {
    return { axisMax: 0, baseline: height - plot.bottom, points: [], ticks: [], values: [] };
  }

  const dataMax = Math.max(...normalized);
  let step = dataMax > 0 ? Math.max(1, niceCeiling(dataMax / Math.max(1, targetIntervals))) : 0;
  let axisMax = step > 0 ? step * Math.ceil(dataMax / step) : 0;

  // Extremely large but finite inputs can overflow while rounding the scale.
  if (!Number.isFinite(axisMax)) {
    axisMax = dataMax;
    step = dataMax / Math.max(1, targetIntervals);
  }

  const scaleMax = axisMax || 1;
  const baseline = height - plot.bottom;
  const plotWidth = Math.max(0, width - plot.left - plot.right);
  const plotHeight = Math.max(0, height - plot.top - plot.bottom);
  const points = normalized.map((value, index) => ({
    value,
    x: normalized.length === 1
      ? plot.left + plotWidth / 2
      : plot.left + (index * plotWidth) / (normalized.length - 1),
    y: plot.top + (1 - value / scaleMax) * plotHeight,
  }));
  const tickCount = step > 0 ? Math.max(1, Math.round(axisMax / step)) : 0;
  const ticks = step > 0
    ? Array.from({ length: tickCount + 1 }, (_, index) => {
      const value = index === tickCount ? 0 : axisMax - index * step;
      return { value, y: plot.top + (1 - value / scaleMax) * plotHeight };
    })
    : [{ value: 0, y: baseline }];

  return { axisMax, baseline, points, ticks, values: normalized };
}

/**
 * Builds geometry for a stacked count chart. Invalid and negative counts are
 * clamped so malformed API records cannot invert bars or corrupt the scale.
 */
export function buildStackedBarModel(buckets, seriesKeys, {
  height = 220,
  plot = DEFAULT_PLOT,
  targetIntervals = 4,
  width = 700,
} = {}) {
  const keys = [...new Set((Array.isArray(seriesKeys) ? seriesKeys : [])
    .map((key) => String(key || "").trim())
    .filter(Boolean))];
  const normalized = (Array.isArray(buckets) ? buckets : []).map((bucket, index) => {
    const values = Object.fromEntries(keys.map((key) => [key, safeCount(bucket?.[key])]));
    return {
      label: String(bucket?.label || `Interval ${index + 1}`),
      total: Object.values(values).reduce((sum, value) => sum + value, 0),
      values,
    };
  });
  const countScale = buildLineChartModel(normalized.map((bucket) => bucket.total), {
    height,
    plot,
    targetIntervals,
    width,
  });
  const baseline = height - plot.bottom;
  const plotWidth = Math.max(0, width - plot.left - plot.right);
  const plotHeight = Math.max(0, height - plot.top - plot.bottom);
  const slotWidth = normalized.length ? plotWidth / normalized.length : 0;
  const barWidth = normalized.length ? Math.max(4, Math.min(32, slotWidth * 0.58)) : 0;
  const scaleMax = countScale.axisMax || 1;
  const bars = normalized.map((bucket, index) => {
    let cursor = baseline;
    const segments = keys.map((key) => {
      const value = bucket.values[key];
      const segmentHeight = (value / scaleMax) * plotHeight;
      cursor -= segmentHeight;
      return { height: segmentHeight, key, value, y: cursor };
    });
    return {
      ...bucket,
      segments,
      width: barWidth,
      x: plot.left + index * slotWidth + (slotWidth - barWidth) / 2,
    };
  });

  return {
    axisMax: countScale.axisMax,
    bars,
    baseline,
    ticks: countScale.ticks,
    total: normalized.reduce((sum, bucket) => sum + bucket.total, 0),
  };
}

/**
 * Selects evenly distributed X-axis labels without crowding narrow charts.
 * The first and last intervals are always retained for temporal context.
 */
export function buildVisibleTickIndexes(pointCount, maxTicks = 6) {
  const count = Math.max(0, Math.floor(Number(pointCount) || 0));
  const limit = Math.max(2, Math.floor(Number(maxTicks) || 2));
  if (count <= limit) return Array.from({ length: count }, (_, index) => index);

  const indexes = new Set([0, count - 1]);
  for (let slot = 1; slot < limit - 1; slot += 1) {
    indexes.add(Math.round((slot * (count - 1)) / (limit - 1)));
  }
  return [...indexes].sort((left, right) => left - right);
}

/** Formats a bounded chart share while keeping tiny non-zero slices visible. */
export function formatChartPercentage(value, total) {
  const safeTotal = safeCount(total);
  const safeValue = safeCount(value);
  if (safeTotal <= 0 || safeValue <= 0) return "0%";
  const percentage = Math.min(100, (safeValue / safeTotal) * 100);
  if (percentage < 0.1) return "<0.1%";
  if (percentage >= 99.95) return "100%";
  return `${percentage.toFixed(1)}%`;
}
