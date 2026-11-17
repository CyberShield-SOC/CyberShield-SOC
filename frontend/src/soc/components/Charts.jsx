import { useCallback, useId, useLayoutEffect, useRef, useState } from "react";
import {
  buildDonutModel,
  buildStackedBarModel,
  buildValueAxis,
  buildVisibleTickIndexes,
  formatChartPercentage,
} from "../utils/chartUtils";

const CHART_FALLBACK_WIDTH = 700;
const CHART_HEIGHT = 236;
// Left leaves room for tick values and the rotated axis title; bottom for
// tick labels plus the x-axis title.
const CHART_PLOT = Object.freeze({ bottom: 46, left: 58, right: 14, top: 12 });
const TWO_LINE_BOTTOM = 58;

function finiteNumber(value) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : 0;
}

function ChartEmpty({ label = "No chart data is available for this time range." }) {
  return <div className="chart-empty" role="status">{label}</div>;
}

function formatChartNumber(value) {
  return new Intl.NumberFormat(undefined, { notation: "compact", maximumFractionDigits: 1 }).format(value);
}

// Tracks the rendered width so the SVG is drawn 1:1 and its text never scales.
function useChartWidth(active, minimum = 240) {
  const [width, setWidth] = useState(CHART_FALLBACK_WIDTH);
  const observer = useRef(null);
  const ref = useCallback((node) => {
    observer.current?.disconnect();
    observer.current = null;
    if (!node) return;
    const update = (next) => {
      if (Number.isFinite(next) && next > 0) setWidth(Math.max(minimum, Math.round(next)));
    };
    update(node.getBoundingClientRect().width);
    if (typeof ResizeObserver === "undefined") return;
    observer.current = new ResizeObserver((entries) => update(entries[0]?.contentRect.width));
    observer.current.observe(node);
  }, [minimum]);
  useLayoutEffect(() => () => observer.current?.disconnect(), []);
  return [active ? ref : undefined, width];
}

function ChartLegend({ items }) {
  return (
    <ul className="chart-key" aria-hidden="true">
      {items.map((item) => <li key={item.key}><i style={{ background: item.color }} />{item.label}</li>)}
    </ul>
  );
}

// Horizontal gridlines, y tick values, x tick labels and both axis titles,
// drawn the same way for every vertical chart.
function CartesianFrame({ width, height, plot, ticks, scaleY, xTicks, xLabel, yLabel }) {
  const baseline = height - plot.bottom;
  return (
    <g className="chart-frame" aria-hidden="true">
      {ticks.map((value) => (
        <g key={value}>
          <line x1={plot.left} x2={width - plot.right} y1={scaleY(value)} y2={scaleY(value)} className={value === 0 ? "chart-baseline" : "chart-grid-line"} />
          <text x={plot.left - 8} y={scaleY(value)} className="chart-axis-value">{formatChartNumber(value)}</text>
        </g>
      ))}
      {xTicks.map((tick) => (
        <text key={tick.key} x={tick.x} y={baseline + 16} textAnchor="middle" className="chart-axis-label">
          {tick.lines.map((line, index) => <tspan key={`${line}-${index}`} x={tick.x} dy={index === 0 ? 0 : 13}>{line}</tspan>)}
        </text>
      ))}
      {yLabel && (
        <text className="chart-axis-title" transform={`translate(13 ${plot.top + (baseline - plot.top) / 2}) rotate(-90)`} textAnchor="middle">{yLabel}</text>
      )}
      {xLabel && (
        <text className="chart-axis-title" x={plot.left + (width - plot.left - plot.right) / 2} y={height - 6} textAnchor="middle">{xLabel}</text>
      )}
    </g>
  );
}

function intervalKeyHandler(count, setActiveIndex) {
  return (event) => {
    const move = (offset) => setActiveIndex((current) => Math.max(0, Math.min(count - 1, (current ?? count - 1) + offset)));
    if (event.key === "ArrowLeft") { event.preventDefault(); move(-1); }
    else if (event.key === "ArrowRight") { event.preventDefault(); move(1); }
    else if (event.key === "Home") { event.preventDefault(); setActiveIndex(0); }
    else if (event.key === "End") { event.preventDefault(); setActiveIndex(count - 1); }
    else if (event.key === "Escape") setActiveIndex(null);
  };
}

// A tooltip box kept inside the chart: it drops below the point when there
// is no room above it.
function ChartTooltip({ x, y, width, chartWidth, lines }) {
  const height = 14 + lines.length * 17;
  const left = Math.max(4, Math.min(chartWidth - width - 4, x - width / 2));
  const top = y - height - 10 >= 2 ? y - height - 10 : y + 12;
  return (
    <g className="chart-tooltip" transform={`translate(${left} ${top})`} aria-hidden="true">
      <rect width={width} height={height} rx="4" />
      {lines.map((line, index) => (
        <g key={`${line.text}-${index}`}>
          {line.swatch && <circle cx="14" cy={19 + index * 17 - 4} r="4" fill={line.swatch} />}
          <text x={line.swatch ? 24 : 10} y={19 + index * 17} className={line.className}>{line.text}</text>
        </g>
      ))}
    </g>
  );
}

// Labels at a fixed stride counted back from the newest interval, so the gaps
// between them are equal and the most recent interval is always labelled.
function xAxisTicks(labels, centers, plotWidth) {
  const maxLabels = Math.max(2, Math.min(8, Math.floor(plotWidth / 92) + 1));
  const stride = Math.max(1, Math.ceil(labels.length / maxLabels));
  const indexes = labels.length <= maxLabels
    ? buildVisibleTickIndexes(labels.length, maxLabels)
    : labels.map((_, index) => index).filter((index) => (labels.length - 1 - index) % stride === 0);
  return indexes.map((index) => ({
    key: `${labels[index]}-${index}`,
    x: centers[index],
    lines: String(labels[index]).split("\n"),
  }));
}

const SPARKLINE_WIDTH = 72;
const SPARKLINE_HEIGHT = 22;

// A minimal inline trend indicator for KPI tiles: no axes, ticks, or tooltip,
// just the shape of the series. Needs at least two points to draw a line.
export function Sparkline({ values = [], color = "var(--soc-accent)" }) {
  const series = (Array.isArray(values) ? values : []).map(finiteNumber);
  if (series.length < 2) return null;
  const max = Math.max(...series, 1);
  const min = Math.min(...series, 0);
  const span = Math.max(max - min, 1);
  const stepX = SPARKLINE_WIDTH / (series.length - 1);
  const points = series
    .map((value, index) => {
      const x = index * stepX;
      const y = SPARKLINE_HEIGHT - ((value - min) / span) * SPARKLINE_HEIGHT;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ");
  return (
    <svg className="kpi-sparkline" viewBox={`0 0 ${SPARKLINE_WIDTH} ${SPARKLINE_HEIGHT}`} preserveAspectRatio="none" aria-hidden="true">
      <polyline points={points} fill="none" stroke={color} strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

// A single IsolationForest decision score plotted against its alert
// threshold on a number line: below the threshold line is the "anomalous"
// zone (lower is more anomalous), so an analyst sees at a glance how far
// past the line a score fell rather than reading two raw floats.
export function ScoreGauge({ score, threshold, belowThreshold }) {
  const safeScore = finiteNumber(score);
  const hasThreshold = typeof threshold === "number" && Number.isFinite(threshold);
  const anchors = [safeScore, 0, ...(hasThreshold ? [threshold] : [])];
  const lo = Math.min(...anchors);
  const hi = Math.max(...anchors);
  const pad = Math.max((hi - lo) * 0.35, 0.03);
  const domainMin = lo - pad;
  const domainMax = hi + pad;
  const span = domainMax - domainMin || 1;
  const toPercent = (value) => Math.min(100, Math.max(0, ((value - domainMin) / span) * 100));
  const scorePct = toPercent(safeScore);
  const thresholdPct = hasThreshold ? toPercent(threshold) : null;
  const anomalous = belowThreshold === true;

  return (
    <div
      className="score-gauge"
      role="img"
      aria-label={`Decision score ${safeScore.toFixed(3)}${hasThreshold ? `, alert threshold ${threshold.toFixed(3)}` : ""}${anomalous ? " — below threshold, flagged anomalous" : ""}`}
    >
      <div className="score-gauge-track">
        {hasThreshold && <span className="score-gauge-zone" style={{ width: `${thresholdPct}%` }} />}
        {hasThreshold && <span className="score-gauge-threshold" style={{ left: `${thresholdPct}%` }} />}
        <span className={`score-gauge-marker${anomalous ? " anomalous" : ""}`} style={{ left: `${scorePct}%` }} />
      </div>
      <div className="score-gauge-labels" aria-hidden="true">
        <span>{domainMin.toFixed(2)}</span>
        {hasThreshold && <span className="score-gauge-threshold-label">threshold {threshold.toFixed(3)}</span>}
        <span>{domainMax.toFixed(2)}</span>
      </div>
    </div>
  );
}

/**
 * One count per time interval, drawn as a line with point markers or as
 * columns. Both share the axes, tooltip and keyboard model.
 */
export function TimeSeriesChart({
  values = [],
  labels = [],
  title,
  variant = "line",
  color = "var(--chart-series-1)",
  unit = "event",
  xLabel = "Time",
  yLabel,
}) {
  const hintId = `soc-chart-hint-${useId().replace(/:/g, "")}`;
  const series = (Array.isArray(values) ? values : []).map((value) => Math.max(0, finiteNumber(value)));
  const [ref, chartWidth] = useChartWidth(series.length > 0);
  const [activeIndex, setActiveIndex] = useState(null);
  if (!series.length) return <ChartEmpty />;

  const safeLabels = Array.isArray(labels) ? labels : [];
  const displayLabels = series.map((_, index) => String(safeLabels[index] || `Interval ${index + 1}`));
  const twoLine = displayLabels.some((label) => label.includes("\n"));
  const plot = { ...CHART_PLOT, bottom: twoLine ? TWO_LINE_BOTTOM : CHART_PLOT.bottom };
  const baseline = CHART_HEIGHT - plot.bottom;
  const plotWidth = chartWidth - plot.left - plot.right;
  const plotHeight = baseline - plot.top;
  const axis = buildValueAxis(Math.max(...series));
  const scaleY = (value) => baseline - (value / axis.axisMax) * plotHeight;
  const slot = plotWidth / series.length;
  const centers = series.map((_, index) => plot.left + slot * (index + 0.5));
  const barWidth = Math.max(2, Math.min(44, slot * 0.62));
  const showMarkers = variant === "line" && series.length <= 60;
  const showValues = variant === "bar" && series.length <= 14 && barWidth >= 18;
  const unitLabel = (count) => `${count.toLocaleString()} ${count === 1 ? unit : `${unit}s`}`;
  const activeLabel = activeIndex === null ? "" : displayLabels[activeIndex].replace(/\s*\n\s*/g, " · ");
  const path = centers.map((x, index) => `${index ? "L" : "M"}${x.toFixed(1)} ${scaleY(series[index]).toFixed(1)}`).join(" ");

  return (
    <div className="line-chart" ref={ref}>
      <svg
        viewBox={`0 0 ${chartWidth} ${CHART_HEIGHT}`}
        width={chartWidth}
        height={CHART_HEIGHT}
        role="group"
        aria-label={title || "Events over time"}
        aria-describedby={hintId}
        tabIndex="0"
        onBlur={() => setActiveIndex(null)}
        onFocus={() => setActiveIndex((current) => current ?? series.length - 1)}
        onKeyDown={intervalKeyHandler(series.length, setActiveIndex)}
        onPointerLeave={(event) => { if (event.pointerType === "mouse") setActiveIndex(null); }}
      >
        <CartesianFrame
          width={chartWidth}
          height={CHART_HEIGHT}
          plot={plot}
          ticks={axis.ticks}
          scaleY={scaleY}
          xTicks={xAxisTicks(displayLabels, centers, plotWidth)}
          xLabel={xLabel}
          yLabel={yLabel || `${unit[0].toUpperCase()}${unit.slice(1)}s`}
        />
        {activeIndex !== null && (
          <rect className="chart-active-band" x={plot.left + slot * activeIndex} y={plot.top} width={slot} height={plotHeight} />
        )}
        {variant === "bar" ? series.map((value, index) => (
          <g key={`${displayLabels[index]}-${index}`}>
            <rect
              className="chart-bar-segment"
              data-active={activeIndex === index || undefined}
              fill={color}
              x={centers[index] - barWidth / 2}
              y={scaleY(value)}
              width={barWidth}
              height={Math.max(0, baseline - scaleY(value))}
            />
            {showValues && value > 0 && (
              <text className="chart-value-label" x={centers[index]} y={scaleY(value) - 6} textAnchor="middle">{formatChartNumber(value)}</text>
            )}
          </g>
        )) : (
          <g>
            <path d={path} className="chart-line" stroke={color} />
            {centers.map((x, index) => ((showMarkers || activeIndex === index) && (
              <circle
                key={`${displayLabels[index]}-${index}`}
                className="chart-point"
                data-active={activeIndex === index || undefined}
                cx={x}
                cy={scaleY(series[index])}
                r={activeIndex === index ? 4.5 : 3}
                stroke={color}
              />
            )))}
          </g>
        )}
        {series.map((_, index) => (
          <rect
            key={`hit-${index}`}
            className="chart-hit-area"
            x={plot.left + slot * index}
            y={plot.top}
            width={slot}
            height={plotHeight}
            onClick={() => setActiveIndex(index)}
            onPointerEnter={() => setActiveIndex(index)}
          />
        ))}
        {activeIndex !== null && (
          <ChartTooltip
            x={centers[activeIndex]}
            y={scaleY(series[activeIndex])}
            width={Math.min(180, chartWidth - 8)}
            chartWidth={chartWidth}
            lines={[
              { text: activeLabel, className: "chart-tooltip-label" },
              { text: unitLabel(series[activeIndex]), className: "chart-tooltip-value", swatch: color },
            ]}
          />
        )}
      </svg>
      <span className="sr-only" id={hintId}>Use Left and Right arrow keys to inspect intervals when the chart is focused.</span>
      <span className="chart-live-value" aria-live="polite">{activeIndex === null ? "" : `${activeLabel}: ${unitLabel(series[activeIndex])}`}</span>
    </div>
  );
}

export function LineAreaChart(props) {
  return <TimeSeriesChart {...props} variant="line" />;
}

export function ColumnChart(props) {
  return <TimeSeriesChart {...props} variant="bar" />;
}

/** Counts per interval split by series, stacked in the order given (first at the bottom). */
export function StackedBarChart({ buckets = [], series = [], title, xLabel = "Time", yLabel = "Alerts" }) {
  const hintId = `soc-stacked-chart-hint-${useId().replace(/:/g, "")}`;
  const normalizedSeries = (Array.isArray(series) ? series : [])
    .filter((item) => item && String(item.key || "").trim())
    .map((item) => ({ color: item.color || "var(--chart-series-1)", key: String(item.key).trim(), label: String(item.label || item.key) }));
  const hasBuckets = Array.isArray(buckets) && buckets.length > 0;
  const [ref, chartWidth] = useChartWidth(hasBuckets);
  const [activeIndex, setActiveIndex] = useState(null);
  const twoLine = hasBuckets && buckets.some((bucket) => String(bucket?.label || "").includes("\n"));
  const plot = { ...CHART_PLOT, bottom: twoLine ? TWO_LINE_BOTTOM : CHART_PLOT.bottom };
  const model = buildStackedBarModel(buckets, normalizedSeries.map((item) => item.key), { height: CHART_HEIGHT, plot, width: chartWidth });
  if (!model.bars.length || model.total <= 0) return <ChartEmpty label="No alerts are available for this time range." />;

  const plotWidth = chartWidth - plot.left - plot.right;
  const plotHeight = model.baseline - plot.top;
  const axisMax = model.axisMax || 1;
  const scaleY = (value) => model.baseline - (value / axisMax) * plotHeight;
  const slot = plotWidth / model.bars.length;
  const centers = model.bars.map((bar) => bar.x + bar.width / 2);
  const activeBar = activeIndex === null ? null : model.bars[activeIndex];
  const activeLabel = activeBar?.label.replace(/\s*\n\s*/g, " · ") || "";
  const breakdown = activeBar ? normalizedSeries.map((item) => `${item.label} ${activeBar.values[item.key]}`).join(", ") : "";
  const ticks = model.ticks.map((tick) => tick.value);

  return (
    <div className="stacked-bar-chart" ref={ref}>
      <ChartLegend items={normalizedSeries} />
      <svg
        viewBox={`0 0 ${chartWidth} ${CHART_HEIGHT}`}
        width={chartWidth}
        height={CHART_HEIGHT}
        role="group"
        aria-label={title || "Alert volume by severity"}
        aria-describedby={hintId}
        tabIndex="0"
        onBlur={() => setActiveIndex(null)}
        onFocus={() => setActiveIndex((current) => current ?? model.bars.length - 1)}
        onKeyDown={intervalKeyHandler(model.bars.length, setActiveIndex)}
        onPointerLeave={(event) => { if (event.pointerType === "mouse") setActiveIndex(null); }}
      >
        <CartesianFrame
          width={chartWidth}
          height={CHART_HEIGHT}
          plot={plot}
          ticks={ticks}
          scaleY={scaleY}
          xTicks={xAxisTicks(model.bars.map((bar) => bar.label), centers, plotWidth)}
          xLabel={xLabel}
          yLabel={yLabel}
        />
        {activeBar && <rect className="chart-active-band" x={plot.left + slot * activeIndex} y={plot.top} width={slot} height={plotHeight} />}
        {model.bars.map((bar, index) => (
          <g className="chart-bar-group" data-active={activeIndex === index || undefined} key={`${bar.label}-${index}`}>
            {bar.segments.map((segment) => segment.height > 0 && (
              <rect
                className="chart-bar-segment"
                fill={normalizedSeries.find((item) => item.key === segment.key)?.color}
                height={segment.height}
                key={segment.key}
                width={bar.width}
                x={bar.x}
                y={segment.y}
              />
            ))}
            <rect
              className="chart-hit-area"
              height={plotHeight}
              onClick={() => setActiveIndex(index)}
              onPointerEnter={() => setActiveIndex(index)}
              width={slot}
              x={plot.left + index * slot}
              y={plot.top}
            />
          </g>
        ))}
        {activeBar && (
          <ChartTooltip
            x={centers[activeIndex]}
            y={scaleY(activeBar.total)}
            width={Math.min(170, chartWidth - 8)}
            chartWidth={chartWidth}
            lines={[
              { text: activeLabel, className: "chart-tooltip-label" },
              { text: `${activeBar.total.toLocaleString()} ${activeBar.total === 1 ? "alert" : "alerts"}`, className: "chart-tooltip-value" },
              ...normalizedSeries.map((item) => ({
                text: `${item.label}: ${activeBar.values[item.key].toLocaleString()}`,
                className: "chart-tooltip-breakdown",
                swatch: item.color,
              })),
            ]}
          />
        )}
      </svg>
      <span className="sr-only" id={hintId}>Use Left and Right arrow keys to inspect alert intervals when the chart is focused.</span>
      <span className="chart-live-value" aria-live="polite">{activeBar ? `${activeLabel}: ${activeBar.total} alerts. ${breakdown}` : ""}</span>
    </div>
  );
}

const DONUT_HEIGHT = 224;

/** Share of a total, with each slice labelled outside the ring on a leader line. */
export function DonutChart({ segments = [], totalLabel = "alerts" }) {
  const normalized = (Array.isArray(segments) ? segments : []).map((segment, index) => ({
    ...segment,
    color: segment?.color || "var(--chart-series-1)",
    label: String(segment?.label || `Series ${index + 1}`),
    value: Math.max(0, finiteNumber(segment?.value)),
  }));
  const total = normalized.reduce((sum, segment) => sum + segment.value, 0);
  const [ref, width] = useChartWidth(total > 0, 220);
  const [active, setActive] = useState(null);
  if (!normalized.length || total <= 0) return <ChartEmpty />;
  const model = buildDonutModel(normalized, { width, height: DONUT_HEIGHT });
  const summary = normalized.map((segment) => `${segment.label} ${segment.value.toLocaleString()} (${formatChartPercentage(segment.value, total)})`).join(", ");
  const dimmed = (label) => (active !== null && active !== label ? "true" : undefined);

  return (
    <div className="donut-svg" ref={ref}>
      <svg viewBox={`0 0 ${width} ${DONUT_HEIGHT}`} width={width} height={DONUT_HEIGHT} role="img" aria-label={`${total.toLocaleString()} ${totalLabel}: ${summary}`}>
        {model.slices.map((slice) => (
          <path
            key={slice.label}
            d={slice.path}
            fill={slice.color}
            className="chart-donut-slice"
            data-dim={dimmed(slice.label)}
            onPointerEnter={() => setActive(slice.label)}
            onPointerLeave={() => setActive(null)}
          >
            <title>{`${slice.label}: ${slice.value.toLocaleString()} (${formatChartPercentage(slice.value, total)})`}</title>
          </path>
        ))}
        <text x={model.cx} y={model.cy + 2} textAnchor="middle" className="chart-donut-total">{total.toLocaleString()}</text>
        <text x={model.cx} y={model.cy + 18} textAnchor="middle" className="chart-donut-caption">{totalLabel}</text>
        {model.slices.map((slice) => {
          const right = slice.side === "right";
          const lineEnd = slice.labelX + (right ? -4 : 4);
          return (
            <g key={`label-${slice.label}`} className="chart-donut-label" data-dim={dimmed(slice.label)} aria-hidden="true">
              <polyline
                points={`${slice.anchor.x.toFixed(1)},${slice.anchor.y.toFixed(1)} ${slice.elbow.x.toFixed(1)},${slice.labelY.toFixed(1)} ${lineEnd.toFixed(1)},${slice.labelY.toFixed(1)}`}
                className="chart-leader"
              />
              <text x={slice.labelX} y={slice.labelY - 3} textAnchor={right ? "start" : "end"} className="chart-donut-name">{slice.label}</text>
              <text x={slice.labelX} y={slice.labelY + 11} textAnchor={right ? "start" : "end"} className="chart-donut-share">
                {slice.value.toLocaleString()} ({formatChartPercentage(slice.value, total)})
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}

// Compact factor bars for small cards: no axis, value at the bar end.
function CompactBars({ items, title }) {
  const max = items.reduce((top, item) => Math.max(top, item.value), 0);
  return (
    <ul className="chart-hbar" aria-label={title}>
      {items.map((item) => (
        <li key={item.key} aria-label={`${item.label}: ${item.value.toLocaleString()}`}>
          <span className="chart-hbar-label" title={item.label}>{item.label}</span>
          <span className="chart-hbar-track" aria-hidden="true">
            <span style={{ width: `${(item.value / max) * 100}%`, background: item.color }} />
          </span>
          <strong>{item.value.toLocaleString()}</strong>
        </li>
      ))}
    </ul>
  );
}

const HBAR_ROW = 28;
const HBAR_THICKNESS = 17;
const HBAR_CHAR = 6.4;

// Items are drawn in the order given, so callers sort them (see sortByValueDesc).
export function HorizontalBarChart({ items = [], title, xLabel, compact = false, labelShare = 0.38, formatValue }) {
  const normalized = (Array.isArray(items) ? items : []).map((item, index) => ({
    key: `${item?.label ?? ""}-${index}`,
    label: String(item?.label ?? `Item ${index + 1}`),
    detail: item?.detail ? String(item.detail) : "",
    color: item?.color || "var(--chart-series-1)",
    value: Math.max(0, finiteNumber(item?.value)),
  }));
  const valueText = (value) => (formatValue ? formatValue(value) : value.toLocaleString());
  const max = normalized.reduce((top, item) => Math.max(top, item.value), 0);
  const [ref, width] = useChartWidth(!compact && max > 0, 220);
  if (!normalized.length || max <= 0) return <ChartEmpty />;
  if (compact) return <CompactBars items={normalized} title={title} />;

  const longest = normalized.reduce((top, item) => Math.max(top, item.label.length), 0);
  const labelWidth = Math.min(width * labelShare, Math.max(48, longest * HBAR_CHAR + 10));
  const plot = { top: 4, right: 40, bottom: xLabel ? 42 : 24, left: labelWidth + 10 };
  const height = plot.top + normalized.length * HBAR_ROW + plot.bottom;
  const plotWidth = width - plot.left - plot.right;
  const axis = buildValueAxis(max);
  const scaleX = (value) => plot.left + (value / axis.axisMax) * plotWidth;
  const baseline = height - plot.bottom;
  const room = Math.floor((labelWidth - 4) / HBAR_CHAR);
  const truncate = (label) => (label.length > room ? `${label.slice(0, Math.max(1, room - 1))}…` : label);

  return (
    <div className="hbar-chart" ref={ref}>
      <svg viewBox={`0 0 ${width} ${height}`} width={width} height={height} role="list" aria-label={title}>
        <g aria-hidden="true">
          {axis.ticks.map((value) => (
            <g key={value}>
              <line x1={scaleX(value)} x2={scaleX(value)} y1={plot.top} y2={baseline} className={value === 0 ? "chart-baseline" : "chart-grid-line"} />
              <text x={scaleX(value)} y={baseline + 15} textAnchor="middle" className="chart-axis-label">{formatChartNumber(value)}</text>
            </g>
          ))}
          {xLabel && <text x={plot.left + plotWidth / 2} y={height - 6} textAnchor="middle" className="chart-axis-title">{xLabel}</text>}
        </g>
        {normalized.map((item, index) => {
          const y = plot.top + index * HBAR_ROW + (HBAR_ROW - HBAR_THICKNESS) / 2;
          const end = scaleX(item.value);
          return (
            <g key={item.key} role="listitem" aria-label={`${item.label}: ${valueText(item.value)}${item.detail ? `, ${item.detail}` : ""}`}>
              <title>{`${item.label}: ${valueText(item.value)}${item.detail ? `\n${item.detail}` : ""}`}</title>
              <text x={plot.left - 10} y={y + HBAR_THICKNESS / 2} textAnchor="end" className="chart-category-label">{truncate(item.label)}</text>
              <rect className="chart-bar-segment" x={plot.left} y={y} width={Math.max(item.value > 0 ? 1.5 : 0, end - plot.left)} height={HBAR_THICKNESS} fill={item.color} />
              <text x={end + 6} y={y + HBAR_THICKNESS / 2} className="chart-value-label chart-value-label-end">{valueText(item.value)}</text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}

// Cell intensity follows the count; the row colour carries the severity.
// The table keeps every value readable and reachable without the colour.
export function HeatmapChart({ columns = [], rows = [], max = 0, title }) {
  if (!rows.length || !columns.length || max <= 0) return <ChartEmpty />;
  return (
    <div className="chart-heatmap">
      <div className="chart-heatmap-scroll" role="region" aria-label={title} tabIndex={0}>
        <table>
          <caption className="sr-only">{title}</caption>
          <thead>
            <tr>
              <th scope="col"><span className="sr-only">Severity</span></th>
              {columns.map((column, index) => <th key={`${column}-${index}`} scope="col">{column}</th>)}
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.key}>
                <th scope="row">{row.label}</th>
                {row.cells.map((value, index) => {
                  const description = `${row.label}, ${columns[index]}: ${value.toLocaleString()}`;
                  const strength = value > 0 ? Math.max(18, (value / max) * 100) : 0;
                  return (
                    <td
                      key={`${row.key}-${index}`}
                      className="chart-heatmap-cell"
                      data-strong={strength >= 60 || undefined}
                      style={value > 0 ? { background: `color-mix(in srgb, ${row.color} ${strength}%, var(--soc-surface-subtle))` } : undefined}
                      title={description}
                      aria-label={description}
                    >
                      {value > 0 ? value.toLocaleString() : ""}
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="chart-heatmap-legend" aria-hidden="true">
        <span>0</span>
        <i />
        <span>{max.toLocaleString()}</span>
        <small>Stronger colour means more alerts. Empty cells had none.</small>
      </div>
    </div>
  );
}

export function CoverageBars({ items = [] }) {
  if (!items.length) return <ChartEmpty label="No coverage data is available." />;
  return (
    <div className="coverage-list">
      {items.map((item) => (
        <div className="coverage-item" key={item.label}>
          <div><span>{item.label}</span><small>{item.value} rules</small></div>
          <div className="coverage-track">
            <span data-tone={item.tone} style={{ width: `${Math.min(100, Math.max(0, (finiteNumber(item.value) / Math.max(finiteNumber(item.total), 1)) * 100))}%` }} />
          </div>
        </div>
      ))}
    </div>
  );
}
