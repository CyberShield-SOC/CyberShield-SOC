import { useLayoutEffect, useRef, useState } from "react";
import { ArrowRight, BrainCircuit } from "../../icons";
import { SOC_ROUTES } from "../../hooks/useAuthRoute";
import { HorizontalBarChart, ScoreGauge } from "./Charts";
import { InlineNotice, LoadingState, Panel, StatusBadge } from "./Ui";
import { formatTimestamp } from "../utils/eventUtils";
import { ENTITY_LABELS } from "../utils/ruleConfig";
import {
  DECISION_SCORE_HELP,
  describePilotStage,
  deviationBars,
  formatDecisionScore,
  pilotLabel,
} from "../utils/mlInsight";

// One scored thing, a real alert or a shadow-mode snapshot, drawn the same
// way: promoting a rule out of shadow mode changes where a finding is filed,
// not what it looks like.
function AnomalyCard({ title, entity, score, threshold, belowThreshold, bars, when, who }) {
  return (
    <li className="dashboard-anomaly-card">
      <header>
        <strong>{title}</strong>
        <span className={`mono ${belowThreshold ? "flagged" : "normal"}`}>{formatDecisionScore(score)}</span>
      </header>
      {entity && (
        <span className="dashboard-anomaly-entity">
          <span>{entity.label}</span>
          <strong title={entity.id}>{entity.id}</strong>
        </span>
      )}
      <ScoreGauge score={score} threshold={threshold} belowThreshold={belowThreshold} />
      {Boolean(bars.length) && (
        <div className="dashboard-anomaly-bars">
          <HorizontalBarChart
            items={bars}
            title={`${title}: contributing factors, standard deviations from the learned baseline`}
            xLabel="Std. deviations from baseline"
            labelShare={0.5}
            formatValue={(value) => value.toFixed(1)}
          />
        </div>
      )}
      <small>
        {who ? `${who} · ` : ""}
        {formatTimestamp(when)}
      </small>
    </li>
  );
}

function PilotStatus({ pilot }) {
  const stage = describePilotStage(pilot);
  const progress = pilot.minSamples ? Math.min(100, Math.round((pilot.sampleCount / pilot.minSamples) * 100)) : 100;
  const label = pilotLabel(pilot.featureSet);
  return (
    <li className="dashboard-anomaly-pilot">
      <header>
        <strong>{label}</strong>
        <StatusBadge status={stage.status} />
      </header>
      <p>
        <span className="sr-only">Stage: </span>{stage.label}. {stage.detail}
      </p>
      {!pilot.activeModel && (
        <div
          className="dashboard-anomaly-progress"
          role="progressbar"
          aria-label={`${label} training samples`}
          aria-valuemin={0}
          aria-valuemax={pilot.minSamples}
          aria-valuenow={Math.min(pilot.sampleCount, pilot.minSamples)}
          data-complete={String(pilot.sampleCount >= pilot.minSamples)}
        >
          <span style={{ width: `${progress}%` }} />
        </div>
      )}
      <small>
        Scores one {ENTITY_LABELS[pilot.entityType]?.toLowerCase() || pilot.entityType} at a time
        {pilot.scoreThreshold !== null ? ` · alert threshold ${formatDecisionScore(pilot.scoreThreshold)}` : ""}
      </small>
    </li>
  );
}

const VISIBLE_ROWS = 2;

/**
 * Caps the findings area at two rows of cards and scrolls the rest. Rows are
 * measured, not assumed: the grid wraps differently at every width and cards
 * differ in height, so a fixed max-height would cut a row in half.
 */
function useRowLimit(rows, contentKey) {
  const ref = useRef(null);
  const [limit, setLimit] = useState({ maxHeight: null, hidden: 0 });

  useLayoutEffect(() => {
    const node = ref.current;
    if (!node) return undefined;
    function measure() {
      const origin = node.getBoundingClientRect().top - node.scrollTop;
      const cards = [...node.querySelectorAll(".dashboard-anomaly-card")].map((card) => {
        const box = card.getBoundingClientRect();
        return { top: Math.round(box.top - origin), bottom: box.bottom - origin };
      });
      const rowTops = [];
      for (const card of cards.slice().sort((a, b) => a.top - b.top)) {
        if (!rowTops.length || card.top - rowTops.at(-1) > 2) rowTops.push(card.top);
      }
      if (rowTops.length <= rows) {
        setLimit((current) => (current.maxHeight === null ? current : { maxHeight: null, hidden: 0 }));
        return;
      }
      const lastTop = rowTops[rows - 1];
      const shown = cards.filter((card) => card.top <= lastTop + 2);
      const maxHeight = Math.ceil(Math.max(...shown.map((card) => card.bottom)) + 4);
      const hidden = cards.length - shown.length;
      setLimit((current) => (current.maxHeight === maxHeight && current.hidden === hidden ? current : { maxHeight, hidden }));
    }
    measure();
    if (typeof ResizeObserver === "undefined") return undefined;
    const observer = new ResizeObserver(measure);
    observer.observe(node);
    return () => observer.disconnect();
  }, [rows, contentKey]);

  return [ref, limit];
}

/**
 * Dashboard panel for the behavioral_anomaly_* rules. Those rules default to
 * shadow mode, so alert rows alone left this panel empty even on a workspace
 * whose trained model had already scored real outliers. It also shows the
 * workspace's `mlAnomalies` resource (GET /ml/anomalies, open to every
 * role), so there is always something true on screen: real alerts when
 * there are any, otherwise the shadow-mode findings, and for pilots with
 * nothing scored yet, how far they are from training.
 */
export function AnomalyDetectionPanel({ alerts, modelStatus, navigate, pilots, loading, error }) {
  const anomalyAlerts = Array.isArray(alerts) ? alerts : [];
  const shadowFindings = pilots.flatMap((pilot) => pilot.scores.map((row) => ({ pilot, row })));
  const flaggedCount = shadowFindings.filter(({ row }) => row.belowThreshold).length;
  const anyLive = pilots.some((pilot) => pilot.activeModel && !pilot.shadowMode);
  const subtitle = modelStatus || (anyLive ? "IsolationForest · alerting" : "IsolationForest · shadow mode");
  const [scrollRef, { maxHeight, hidden }] = useRowLimit(VISIBLE_ROWS, `${anomalyAlerts.length}:${shadowFindings.length}:${loading}`);
  const scrolls = maxHeight !== null;

  return (
    <Panel
      className="dashboard-anomaly-panel"
      title="Behavioral Anomaly Detection"
      subtitle={subtitle}
      actions={(
        <span className="detection-method-badge ml">
          <BrainCircuit size={12} aria-hidden="true" /> {anyLive ? "ML alerting" : "ML shadow mode"}
        </span>
      )}
    >
      {error && <InlineNotice tone="error" title="Findings unavailable">{error}</InlineNotice>}

      <div
        className="dashboard-anomaly-scroll"
        ref={scrollRef}
        data-scrolls={scrolls || undefined}
        style={scrolls ? { maxHeight } : undefined}
        role={scrolls ? "region" : undefined}
        aria-label={scrolls ? "Anomaly findings, scroll for more" : undefined}
        tabIndex={scrolls ? 0 : undefined}
      >
        {Boolean(anomalyAlerts.length) && (
          <div className="dashboard-anomaly-section">
            <h3>Raised alerts<small>{anomalyAlerts.length} in this time range</small></h3>
            <ol className="dashboard-anomaly-cards">
              {anomalyAlerts.map((alert) => {
                const insight = alert.mlInsight;
                const bars = deviationBars(insight?.deviations);
                return (
                  <AnomalyCard
                    key={alert.id}
                    title={alert.title}
                    score={insight?.score}
                    threshold={insight?.threshold}
                    belowThreshold={insight?.belowThreshold === true}
                    bars={bars}
                    when={alert.createdAt}
                    who={alert.user && alert.user !== "system" ? alert.user : ""}
                  />
                );
              })}
            </ol>
          </div>
        )}

        {!loading && Boolean(shadowFindings.length) && (
          <div className="dashboard-anomaly-section">
            <h3>
              {anomalyAlerts.length ? "Shadow-mode findings" : "Most unusual recent activity"}
              <small>{flaggedCount ? `${flaggedCount} below the alert threshold` : "none below the alert threshold"}</small>
            </h3>
            <ol className="dashboard-anomaly-cards">
              {shadowFindings.map(({ pilot, row }) => (
                <AnomalyCard
                  key={`${pilot.featureSet}-${row.id ?? `${row.entityId}-${row.capturedAt}`}`}
                  title={pilotLabel(pilot.featureSet)}
                  entity={{ label: ENTITY_LABELS[pilot.entityType] || pilot.entityType, id: row.entityId }}
                  score={row.score}
                  threshold={pilot.scoreThreshold}
                  belowThreshold={row.belowThreshold}
                  bars={deviationBars(row.deviations)}
                  when={row.capturedAt}
                />
              ))}
            </ol>
          </div>
        )}
      </div>
      {scrolls && (
        <p className="dashboard-anomaly-more" aria-hidden="true">
          Showing {VISIBLE_ROWS} rows · scroll for {hidden} more {hidden === 1 ? "finding" : "findings"}
        </p>
      )}

      {loading ? (
        <LoadingState label="Loading anomaly findings…" />
      ) : (
        <>
          {Boolean(pilots.length) && (
            <div className="dashboard-anomaly-section">
              <h3>Model status<small>{pilots.length} learned-behavior pilots</small></h3>
              <ul className="dashboard-anomaly-pilots">
                {pilots.map((pilot) => <PilotStatus key={pilot.featureSet} pilot={pilot} />)}
              </ul>
            </div>
          )}

          {!pilots.length && !anomalyAlerts.length && !error && (
            <p className="empty-inline">No behavioral-anomaly pilots are registered on this backend.</p>
          )}
        </>
      )}

      <div className="dashboard-anomaly-footer">
        <div className="dashboard-anomaly-help">
          <small className="ai-sample-note">{DECISION_SCORE_HELP}</small>
          <ul className="chart-key" aria-label="Factor bar colours">
            <li><i style={{ background: "var(--chart-anomaly-above)" }} />Above the learned baseline</li>
            <li><i style={{ background: "var(--chart-anomaly-below)" }} />Below the learned baseline</li>
          </ul>
        </div>
        <button className="soc-text-button" type="button" onClick={() => navigate(anomalyAlerts.length ? SOC_ROUTES.alerts : SOC_ROUTES.threatDetection)}>
          {anomalyAlerts.length ? "Review in Alerts" : "Model training and shadow mode"} <ArrowRight size={13} aria-hidden="true" />
        </button>
      </div>
    </Panel>
  );
}
