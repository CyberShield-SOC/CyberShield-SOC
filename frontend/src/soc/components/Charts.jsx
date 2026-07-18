import { useId, useLayoutEffect, useRef, useState } from "react";
import {
  buildLineChartModel,
  buildStackedBarModel,
  buildVisibleTickIndexes,
  formatChartPercentage,
} from "../utils/chartUtils";

const CHART_FALLBACK_WIDTH = 700;
const CHART_HEIGHT = 220;
const CHART_PLOT = Object.freeze({ bottom: 40, left: 52, right: 18, top: 16 });

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

export function LineAreaChart({ values = [], labels = [], title }) {
  const chartRef = useRef(null);
  const gradientId = `soc-area-${useId().replace(/:/g, "")}`;
  const hintId = `soc-chart-hint-${useId().replace(/:/g, "")}`;
  const [chartWidth, setChartWidth] = useState(CHART_FALLBACK_WIDTH);
  const [activeIndex, setActiveIndex] = useState(null);

  useLayoutEffect(() => {
    const chart = chartRef.current;
    if (!chart) return undefined;

    function updateWidth(width) {
      if (!Number.isFinite(width) || width <= 0) return;
      setChartWidth(Math.max(320, Math.round(width)));
    }

    updateWidth(chart.getBoundingClientRect().width);
    if (typeof ResizeObserver === "undefined") return undefined;

    const observer = new ResizeObserver((entries) => {
      updateWidth(entries[0]?.contentRect.width);
    });
    observer.observe(chart);
    return () => observer.disconnect();
  }, [values]);

  const { baseline, points, ticks } = buildLineChartModel(values, {
    height: CHART_HEIGHT,
    plot: CHART_PLOT,
    width: chartWidth,
  });
  if (!points.length) return <ChartEmpty />;
  const safeLabels = Array.isArray(labels) ? labels : [];
  const displayLabels = points.map((_, index) => String(safeLabels[index] || `Interval ${index + 1}`));
  const plotWidth = chartWidth - CHART_PLOT.left - CHART_PLOT.right;
  const maxXAxisLabels = Math.max(2, Math.min(6, Math.floor(plotWidth / 125) + 1));
  const visibleLabelIndexes = new Set(buildVisibleTickIndexes(points.length, maxXAxisLabels));
  const line = points.map((point) => `${point.x},${point.y}`).join(" ");
  const area = `M ${points[0].x} ${baseline} L ${line.replace(/ /g, " L ")} L ${points.at(-1).x} ${baseline} Z`;
  const activePoint = activeIndex === null ? null : points[activeIndex];
  const tooltipLabel = activeIndex === null ? "" : displayLabels[activeIndex].replace(/\s*\n\s*/g, " · ");
  const tooltipWidth = 172;
  const tooltipHeight = 54;
  const tooltipX = activePoint
    ? Math.max(4, Math.min(chartWidth - tooltipWidth - 4, activePoint.x - tooltipWidth / 2))
    : 0;
  const tooltipY = activePoint ? Math.max(4, activePoint.y - tooltipHeight - 10) : 0;

  function moveSelection(offset) {
    setActiveIndex((current) => {
      const startingIndex = current === null ? points.length - 1 : current;
      return Math.max(0, Math.min(points.length - 1, startingIndex + offset));
    });
  }

  function handleKeyDown(event) {
    if (event.key === "ArrowLeft") {
      event.preventDefault();
      moveSelection(-1);
    } else if (event.key === "ArrowRight") {
      event.preventDefault();
      moveSelection(1);
    } else if (event.key === "Home") {
      event.preventDefault();
      setActiveIndex(0);
    } else if (event.key === "End") {
      event.preventDefault();
      setActiveIndex(points.length - 1);
    } else if (event.key === "Escape") {
      setActiveIndex(null);
    }
  }

  return (
    <div className="line-chart" ref={chartRef}>
      <svg
        viewBox={`0 0 ${chartWidth} ${CHART_HEIGHT}`}
        role="group"
        aria-label={title || "Events over time"}
        aria-describedby={hintId}
        tabIndex="0"
        onBlur={() => setActiveIndex(null)}
        onFocus={() => setActiveIndex((current) => current ?? points.length - 1)}
        onKeyDown={handleKeyDown}
        onPointerLeave={(event) => {
          // Keep a tapped interval selected on touch devices; mouse tooltips may dismiss on exit.
          if (event.pointerType === "mouse") setActiveIndex(null);
        }}
      >
        <defs>
          <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" stopColor="var(--soc-accent-bright)" stopOpacity="0.42" />
            <stop offset="0.72" stopColor="var(--soc-accent)" stopOpacity="0.14" />
            <stop offset="1" stopColor="var(--soc-accent)" stopOpacity="0.02" />
          </linearGradient>
        </defs>
        {ticks.map((tick) => (
          <g key={tick.value}>
            {tick.value !== 0 && <line x1={CHART_PLOT.left} y1={tick.y} x2={chartWidth - CHART_PLOT.right} y2={tick.y} className="chart-grid-line" />}
            <text x={CHART_PLOT.left - 8} y={tick.y} className="chart-axis-value">{formatChartNumber(tick.value)}</text>
          </g>
        ))}
        <line x1={CHART_PLOT.left} y1={CHART_PLOT.top} x2={CHART_PLOT.left} y2={baseline} className="chart-axis-line" />
        <line x1={CHART_PLOT.left} y1={baseline} x2={chartWidth - CHART_PLOT.right} y2={baseline} className="chart-axis-line" />
        <path d={area} fill={`url(#${gradientId})`} />
        <polyline points={line} className="chart-line" />
        {points.map((point, index) => (
          <g key={`${displayLabels[index]}-${index}`}>
            <rect
              className="chart-hit-area"
              x={index === 0 ? CHART_PLOT.left : (points[index - 1].x + point.x) / 2}
              y={CHART_PLOT.top}
              width={(index === points.length - 1 ? chartWidth - CHART_PLOT.right : (point.x + points[index + 1].x) / 2) - (index === 0 ? CHART_PLOT.left : (points[index - 1].x + point.x) / 2)}
              height={baseline - CHART_PLOT.top}
              onClick={() => setActiveIndex(index)}
              onPointerEnter={() => setActiveIndex(index)}
              onPointerMove={() => setActiveIndex(index)}
            />
            <circle cx={point.x} cy={point.y} r={activeIndex === index ? 6 : 4} className="chart-point" data-active={activeIndex === index || undefined} />
          </g>
        ))}
        {activePoint && (
          <g className="chart-active-layer" aria-hidden="true">
            <line x1={activePoint.x} y1={CHART_PLOT.top} x2={activePoint.x} y2={baseline} className="chart-active-guide" />
            <g className="chart-tooltip" transform={`translate(${tooltipX} ${tooltipY})`}>
              <rect width={tooltipWidth} height={tooltipHeight} rx="7" />
              <text x="12" y="20">{tooltipLabel}</text>
              <text x="12" y="41" className="chart-tooltip-value">{activePoint.value.toLocaleString()} {activePoint.value === 1 ? "event" : "events"}</text>
            </g>
          </g>
        )}
        <g className="chart-x-axis" aria-hidden="true">
          {points.map((point, index) => {
            if (!visibleLabelIndexes.has(index)) return null;
            const lines = displayLabels[index].split("\n");
            const textAnchor = index === 0 ? "start" : index === points.length - 1 ? "end" : "middle";
            return (
              <g key={`${displayLabels[index]}-axis-${index}`}>
                <line x1={point.x} y1={baseline} x2={point.x} y2={baseline + 5} className="chart-axis-tick" />
                <text x={point.x} y={baseline + 20} textAnchor={textAnchor} className="chart-axis-label">
                  {lines.map((labelLine, lineIndex) => (
                    <tspan key={`${labelLine}-${lineIndex}`} x={point.x} dy={lineIndex === 0 ? 0 : 13}>{labelLine}</tspan>
                  ))}
                </text>
              </g>
            );
          })}
        </g>
      </svg>
      <span className="sr-only" id={hintId}>Use Left and Right arrow keys to inspect intervals when the chart is focused.</span>
      <span className="chart-live-value" aria-live="polite">
        {activePoint ? `${tooltipLabel}: ${activePoint.value} ${activePoint.value === 1 ? "event" : "events"}` : ""}
      </span>
    </div>
  );
}

export function StackedBarChart({ buckets = [], series = [], title }) {
  const chartRef = useRef(null);
  const hintId = `soc-stacked-chart-hint-${useId().replace(/:/g, "")}`;
  const [chartWidth, setChartWidth] = useState(CHART_FALLBACK_WIDTH);
  const [activeIndex, setActiveIndex] = useState(null);

  useLayoutEffect(() => {
    const chart = chartRef.current;
    if (!chart) return undefined;

    function updateWidth(width) {
      if (!Number.isFinite(width) || width <= 0) return;
      setChartWidth(Math.max(320, Math.round(width)));
    }

    updateWidth(chart.getBoundingClientRect().width);
    if (typeof ResizeObserver === "undefined") return undefined;

    const observer = new ResizeObserver((entries) => updateWidth(entries[0]?.contentRect.width));
    observer.observe(chart);
    return () => observer.disconnect();
  }, [buckets, series]);

  const normalizedSeries = (Array.isArray(series) ? series : [])
    .filter((item) => item && String(item.key || "").trim())
    .map((item) => ({
      color: item.color || "var(--soc-accent)",
      key: String(item.key).trim(),
      label: String(item.label || item.key),
    }));
  const model = buildStackedBarModel(buckets, normalizedSeries.map((item) => item.key), {
    height: CHART_HEIGHT,
    plot: CHART_PLOT,
    width: chartWidth,
  });
  if (!model.bars.length || model.total <= 0) {
    return <ChartEmpty label="No alerts are available for this time range." />;
  }

  const plotWidth = chartWidth - CHART_PLOT.left - CHART_PLOT.right;
  const slotWidth = plotWidth / model.bars.length;
  const maxXAxisLabels = Math.max(2, Math.min(6, Math.floor(plotWidth / 120) + 1));
  const visibleLabelIndexes = new Set(buildVisibleTickIndexes(model.bars.length, maxXAxisLabels));
  const activeBar = activeIndex === null ? null : model.bars[activeIndex];
  const tooltipWidth = Math.min(220, chartWidth - 8);
  const tooltipHeight = 98;
  const activeCenter = activeBar ? activeBar.x + activeBar.width / 2 : 0;
  const activeTop = activeBar ? Math.min(...activeBar.segments.map((segment) => segment.y)) : 0;
  const tooltipX = activeBar
    ? Math.max(4, Math.min(chartWidth - tooltipWidth - 4, activeCenter - tooltipWidth / 2))
    : 0;
  const tooltipY = activeBar ? Math.max(4, activeTop - tooltipHeight - 9) : 0;
  const tooltipLabel = activeBar?.label.replace(/\s*\n\s*/g, " · ") || "";
  const tooltipBreakdown = activeBar
    ? normalizedSeries.map((item) => `${item.label} ${activeBar.values[item.key]}`).join(" · ")
    : "";
  const tooltipBreakdownRows = activeBar
    ? [normalizedSeries.slice(0, 2), normalizedSeries.slice(2, 4)]
      .filter((row) => row.length)
      .map((row) => row.map((item) => `${item.label} ${activeBar.values[item.key]}`).join(" · "))
    : [];

  function moveSelection(offset) {
    setActiveIndex((current) => {
      const startingIndex = current === null ? model.bars.length - 1 : current;
      return Math.max(0, Math.min(model.bars.length - 1, startingIndex + offset));
    });
  }

  function handleKeyDown(event) {
    if (event.key === "ArrowLeft") {
      event.preventDefault();
      moveSelection(-1);
    } else if (event.key === "ArrowRight") {
      event.preventDefault();
      moveSelection(1);
    } else if (event.key === "Home") {
      event.preventDefault();
      setActiveIndex(0);
    } else if (event.key === "End") {
      event.preventDefault();
      setActiveIndex(model.bars.length - 1);
    } else if (event.key === "Escape") {
      setActiveIndex(null);
    }
  }

  return (
    <div className="stacked-bar-chart" ref={chartRef}>
      <svg
        viewBox={`0 0 ${chartWidth} ${CHART_HEIGHT}`}
        role="group"
        aria-label={title || "Alert volume by severity"}
        aria-describedby={hintId}
        tabIndex="0"
        onBlur={() => setActiveIndex(null)}
        onFocus={() => setActiveIndex((current) => current ?? model.bars.length - 1)}
        onKeyDown={handleKeyDown}
        onPointerLeave={(event) => {
          if (event.pointerType === "mouse") setActiveIndex(null);
        }}
      >
        {model.ticks.map((tick) => (
          <g key={tick.value}>
            {tick.value !== 0 && <line x1={CHART_PLOT.left} y1={tick.y} x2={chartWidth - CHART_PLOT.right} y2={tick.y} className="chart-grid-line" />}
            <text x={CHART_PLOT.left - 8} y={tick.y} className="chart-axis-value">{formatChartNumber(tick.value)}</text>
          </g>
        ))}
        <line x1={CHART_PLOT.left} y1={CHART_PLOT.top} x2={CHART_PLOT.left} y2={model.baseline} className="chart-axis-line" />
        <line x1={CHART_PLOT.left} y1={model.baseline} x2={chartWidth - CHART_PLOT.right} y2={model.baseline} className="chart-axis-line" />
        {model.bars.map((bar, index) => (
          <g className="chart-bar-group" data-active={activeIndex === index || undefined} key={`${bar.label}-${index}`}>
            {bar.segments.map((segment) => (
              segment.height > 0 && (
                <rect
                  className="chart-bar-segment"
                  fill={normalizedSeries.find((item) => item.key === segment.key)?.color}
                  height={segment.height}
                  key={segment.key}
                  rx={segment.height >= 4 ? 2 : 0}
                  width={bar.width}
                  x={bar.x}
                  y={segment.y}
                />
              )
            ))}
            {activeIndex === index && (
              <rect
                className="chart-bar-outline"
                height={model.baseline - Math.min(...bar.segments.map((segment) => segment.y))}
                rx="3"
                width={bar.width + 4}
                x={bar.x - 2}
                y={Math.min(...bar.segments.map((segment) => segment.y))}
              />
            )}
            <rect
              className="chart-hit-area"
              height={model.baseline - CHART_PLOT.top}
              onClick={() => setActiveIndex(index)}
              onPointerEnter={() => setActiveIndex(index)}
              onPointerMove={() => setActiveIndex(index)}
              width={slotWidth}
              x={CHART_PLOT.left + index * slotWidth}
              y={CHART_PLOT.top}
            />
          </g>
        ))}
        <g className="chart-x-axis" aria-hidden="true">
          {model.bars.map((bar, index) => {
            if (!visibleLabelIndexes.has(index)) return null;
            const x = bar.x + bar.width / 2;
            const lines = bar.label.split("\n");
            const textAnchor = index === 0 ? "start" : index === model.bars.length - 1 ? "end" : "middle";
            return (
              <g key={`${bar.label}-axis-${index}`}>
                <line x1={x} y1={model.baseline} x2={x} y2={model.baseline + 5} className="chart-axis-tick" />
                <text x={x} y={model.baseline + 20} textAnchor={textAnchor} className="chart-axis-label">
                  {lines.map((line, lineIndex) => (
                    <tspan key={`${line}-${lineIndex}`} x={x} dy={lineIndex === 0 ? 0 : 13}>{line}</tspan>
                  ))}
                </text>
              </g>
            );
          })}
        </g>
        {activeBar && (
          <g className="chart-active-layer chart-tooltip" aria-hidden="true" transform={`translate(${tooltipX} ${tooltipY})`}>
            <rect width={tooltipWidth} height={tooltipHeight} rx="7" />
            <text x="12" y="20">{tooltipLabel}</text>
            <text x="12" y="42" className="chart-tooltip-value">{activeBar.total.toLocaleString()} {activeBar.total === 1 ? "alert" : "alerts"}</text>
            {tooltipBreakdownRows.map((row, rowIndex) => (
              <text x="12" y={66 + rowIndex * 16} className="chart-tooltip-breakdown" key={row}>{row}</text>
            ))}
          </g>
        )}
      </svg>
      <span className="sr-only" id={hintId}>Use Left and Right arrow keys to inspect alert intervals when the chart is focused.</span>
      <span className="chart-live-value" aria-live="polite">
        {activeBar ? `${tooltipLabel}: ${activeBar.total} alerts. ${tooltipBreakdown}` : ""}
      </span>
    </div>
  );
}

export function DonutChart({ segments = [], totalLabel = "alerts" }) {
  const normalized = (Array.isArray(segments) ? segments : []).map((segment, index) => ({
    ...segment,
    color: segment?.color || "var(--soc-accent)",
    label: String(segment?.label || `Series ${index + 1}`),
    value: Math.max(0, finiteNumber(segment?.value)),
  }));
  const total = normalized.reduce((sum, segment) => sum + segment.value, 0);
  if (!normalized.length || total <= 0) return <ChartEmpty />;
  const visibleSegments = normalized.filter((segment) => segment.value > 0);
  let cursor = 0;
  const stops = visibleSegments.flatMap((segment) => {
    const start = (cursor / total) * 360;
    cursor += segment.value;
    const end = (cursor / total) * 360;
    const segmentSpan = end - start;
    // A bounded separator preserves tiny non-zero slices while still giving
    // every visible severity a clear visual boundary.
    const halfGap = visibleSegments.length > 1
      ? Math.min(1.2, segmentSpan * 0.2)
      : 0;
    return [
      `var(--soc-surface) ${start}deg ${start + halfGap}deg`,
      `${segment.color} ${start + halfGap}deg ${end - halfGap}deg`,
      `var(--soc-surface) ${end - halfGap}deg ${end}deg`,
    ];
  });

  return (
    <div className="donut-layout">
      <div className="donut-chart" style={{ background: `conic-gradient(${stops.join(",")})` }} role="img" aria-label={`${total.toLocaleString()} ${totalLabel}`}>
        <span><strong>{total.toLocaleString()}</strong><small>{totalLabel}</small></span>
      </div>
      <ul className="chart-legend">
        {normalized.map((segment, index) => (
          <li key={`${segment.label}-${index}`} aria-label={`${segment.label}: ${segment.value.toLocaleString()} (${formatChartPercentage(segment.value, total)})`}>
            <i style={{ background: segment.color }} />
            <span>{segment.label}</span>
            <strong>
              <span>{segment.value.toLocaleString()}</span>
              <small>({formatChartPercentage(segment.value, total)})</small>
            </strong>
          </li>
        ))}
      </ul>
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

export function MiniBars({ values = [], labels = [] }) {
  const normalized = values.map((value) => Math.max(0, finiteNumber(value)));
  if (!normalized.length) return <ChartEmpty />;
  const max = Math.max(1, ...normalized);
  return (
    <div className="mini-bars" role="img" aria-label="Analysis result distribution">
      {normalized.map((value, index) => (
        <div key={labels[index] || index}>
          <span style={{ height: `${Math.max((value / max) * 100, 8)}%` }} />
          {labels[index] && <small>{labels[index]}</small>}
        </div>
      ))}
    </div>
  );
}
