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
  const axis = dataMax > 0 ? buildValueAxis(dataMax, targetIntervals) : null;
  let step = axis ? axis.ticks[1] - axis.ticks[0] : 0;
  let axisMax = axis ? axis.axisMax : 0;

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
  const barWidth = normalized.length ? Math.max(3, Math.min(44, slotWidth * 0.62)) : 0;
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

/**
 * A rounded value axis for a count measure: 0 to a "nice" maximum in even
 * steps (1, 2 or 5 times a power of ten), so tick labels read like a real
 * chart's (0, 50, 100, 150) instead of raw data values.
 */
export function buildValueAxis(maxValue, targetIntervals = 4) {
  const max = safeCount(maxValue);
  if (max <= 0) return { axisMax: 1, ticks: [0, 1] };
  // The smallest whole 1/2/5 step that fits in at most targetIntervals + 1
  // intervals keeps the axis close to the data (428 gets 0-500, not 0-600).
  const limit = Math.max(1, targetIntervals) + 1;
  let step = 1;
  for (let magnitude = 1; ; magnitude *= 10) {
    const found = [1, 2, 5].map((factor) => factor * magnitude).find((candidate) => Math.ceil(max / candidate) <= limit);
    if (found) { step = found; break; }
    if (!Number.isFinite(magnitude * 10)) { step = max / limit; break; }
  }
  const axisMax = step * Math.ceil(max / step);
  const ticks = [];
  for (let value = 0; value <= axisMax + step / 2; value += step) ticks.push(value);
  return { axisMax, ticks };
}

const DONUT_START = -Math.PI / 2;

function polar(cx, cy, radius, angle) {
  return { x: cx + radius * Math.cos(angle), y: cy + radius * Math.sin(angle) };
}

/** SVG path for one ring segment between two angles (radians, clockwise). */
export function donutArcPath(cx, cy, outer, inner, start, end) {
  // A full circle cannot be drawn as one arc: stop just short of it.
  const sweep = Math.min(end - start, Math.PI * 2 - 1e-4);
  const finish = start + sweep;
  const large = sweep > Math.PI ? 1 : 0;
  const a = polar(cx, cy, outer, start);
  const b = polar(cx, cy, outer, finish);
  const c = polar(cx, cy, inner, finish);
  const d = polar(cx, cy, inner, start);
  const f = (n) => n.toFixed(2);
  return [
    `M${f(a.x)} ${f(a.y)}`,
    `A${f(outer)} ${f(outer)} 0 ${large} 1 ${f(b.x)} ${f(b.y)}`,
    `L${f(c.x)} ${f(c.y)}`,
    `A${f(inner)} ${f(inner)} 0 ${large} 0 ${f(d.x)} ${f(d.y)}`,
    "Z",
  ].join(" ");
}

/**
 * Geometry for a donut with outside labels joined by leader lines. Labels sit
 * on the side their slice faces and are pushed apart vertically so they never
 * overlap, however small the slices are. Zero slices are left out.
 */
export function buildDonutModel(segments, {
  height = 220,
  labelGap = 30,
  labelSpace = 74,
  maxRadius = 92,
  minRadius = 36,
  width = 320,
} = {}) {
  const items = (Array.isArray(segments) ? segments : [])
    .map((segment) => ({ ...segment, value: safeCount(segment?.value) }))
    .filter((segment) => segment.value > 0);
  const total = items.reduce((sum, segment) => sum + segment.value, 0);
  if (!items.length || total <= 0) return { cx: 0, cy: 0, inner: 0, outer: 0, slices: [], total: 0 };

  const cx = width / 2;
  const cy = height / 2;
  const outer = Math.max(minRadius, Math.min(maxRadius, height / 2 - 16, (width - labelSpace * 2) / 2 - 18));
  const inner = outer * 0.7;
  let cursor = DONUT_START;
  const slices = items.map((segment) => {
    const start = cursor;
    const end = cursor + (segment.value / total) * Math.PI * 2;
    cursor = end;
    const mid = (start + end) / 2;
    const side = Math.cos(mid) >= 0 ? "right" : "left";
    const anchor = polar(cx, cy, outer + 3, mid);
    const elbow = polar(cx, cy, outer + 12, mid);
    return {
      ...segment,
      anchor,
      elbow,
      end,
      labelY: elbow.y,
      path: donutArcPath(cx, cy, outer, inner, start, end),
      side,
      start,
    };
  });

  // Spread each side's labels so neighbours keep at least labelGap between them.
  const top = 12;
  const bottom = height - labelGap + 6;
  for (const side of ["left", "right"]) {
    const column = slices.filter((slice) => slice.side === side).sort((a, b) => a.labelY - b.labelY);
    for (let index = 0; index < column.length; index += 1) {
      const floor = index === 0 ? top : column[index - 1].labelY + labelGap;
      column[index].labelY = Math.max(column[index].labelY, floor);
    }
    for (let index = column.length - 1; index >= 0; index -= 1) {
      const ceiling = index === column.length - 1 ? bottom : column[index + 1].labelY - labelGap;
      column[index].labelY = Math.min(column[index].labelY, ceiling);
    }
  }
  for (const slice of slices) {
    const direction = slice.side === "right" ? 1 : -1;
    slice.labelX = cx + direction * (outer + 24);
  }
  return { cx, cy, inner, outer, slices, total };
}
