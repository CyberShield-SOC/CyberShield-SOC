import {
  Activity,
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  ExternalLink,
  Network,
  ShieldAlert,
  ShieldCheck,
  UsersRound,
} from "lucide-react";
import { SOC_ROUTES } from "../../hooks/useAuthRoute";
import { CoverageBars, DonutChart, LineAreaChart, StackedBarChart } from "../components/Charts";
import {
  ErrorState,
  LoadingState,
  PageHeader,
  Panel,
  SeverityBadge,
  StatusBadge,
} from "../components/Ui";
import { useSocWorkspace } from "../context/SocWorkspaceContext";
import {
  deriveAnalystWorkload,
  deriveTelemetryReadiness,
  deriveThreatAnalysis,
} from "../utils/dashboardMetrics";
import { formatTimestamp } from "../utils/eventUtils";
import { isTerminalIncidentStatus } from "../utils/incidentWorkflow";
import { summarizeSourceActivity } from "../utils/ipLocation";
import {
  buildSeverityBuckets,
  buildTimeBuckets,
  calculateSecurityGrade,
  summarizeIpActivity,
  TIME_RANGE_LABELS,
} from "../utils/timeRange";

const SEVERITY_COLORS = {
  critical: "var(--severity-critical)",
  high: "var(--severity-high)",
  medium: "var(--severity-medium)",
  low: "var(--severity-low)",
};

const STACKED_SEVERITY_SERIES = Object.freeze([
  { key: "low", label: "Low", color: SEVERITY_COLORS.low },
  { key: "medium", label: "Medium", color: SEVERITY_COLORS.medium },
  { key: "high", label: "High", color: SEVERITY_COLORS.high },
  { key: "critical", label: "Critical", color: SEVERITY_COLORS.critical },
]);

function DashboardSummaryCard({ detail, icon: Icon, label, onClick, tone = "default", value }) {
  return (
    <button
      className="dashboard-summary-card"
      data-card-tone={tone}
      type="button"
      onClick={onClick}
      aria-label={`${label}: ${value}. ${detail}`}
    >
      <span className="dashboard-summary-icon"><Icon size={18} aria-hidden="true" /></span>
      <span className="dashboard-summary-copy">
        <small>{label}</small>
        <strong>{value}</strong>
        <span>{detail}</span>
      </span>
      <ArrowRight className="dashboard-summary-arrow" size={14} aria-hidden="true" />
    </button>
  );
}

export default function DashboardPage({ navigate }) {
  const {
    dashboard: data,
    globalTimeRange,
    timeFilteredAlerts: alerts,
    timeFilteredIngestedEvents: events,
    timeFilteredIncidents: incidents,
    resources,
    refresh,
    setSelectedAlertId,
    setGlobalTimeRange,
  } = useSocWorkspace();
  // Every KPI and finding is derived from the authoritative record resources.
  // The optional dashboard aggregate only enriches detection coverage, so a
  // delayed aggregate response never blocks otherwise usable backend data.
  const loading = resources.alerts.loading || resources.events.loading || resources.incidents.loading;
  const error = resources.alerts.error || resources.events.error || resources.incidents.error;

  if (loading) return <LoadingState label="Loading security posture…" />;
  if (error) {
    return (
      <ErrorState
        message={error}
        onRetry={() => Promise.all([refresh("events"), refresh("alerts"), refresh("incidents")])}
      />
    );
  }

  const rangeLabel = TIME_RANGE_LABELS[globalTimeRange];
  const activeAlerts = alerts.filter((alert) => !["contained", "resolved", "closed", "false positive"].includes(alert.status));
  const openIncidents = incidents.filter((incident) => !isTerminalIncidentStatus(incident.status));
  const completedIncidents = incidents.length - openIncidents.length;
  const containedAlerts = alerts.filter((alert) => ["contained", "resolved", "closed"].includes(alert.status)).length;
  const ingestion = buildTimeBuckets(events, globalTimeRange, ["ingestedAt", "timestamp"]);
  const severityBuckets = buildSeverityBuckets(alerts, globalTimeRange);
  const securityGrade = calculateSecurityGrade({ alerts, incidents, events });
  const ipActivity = summarizeIpActivity(events);
  const severity = Object.keys(SEVERITY_COLORS).map((key) => ({
    label: key[0].toUpperCase() + key.slice(1),
    value: alerts.filter((alert) => alert.severity === key).length,
    color: SEVERITY_COLORS[key],
  }));
  const triggeredRules = new Set(alerts.map((alert) => alert.ruleId).filter(Boolean)).size;
  const coverageItems = Array.isArray(data?.coverage) && data.coverage.length
    ? data.coverage
    : [{ label: "Triggered rules", value: triggeredRules, total: Math.max(triggeredRules, 1) }];
  const coverageTotals = coverageItems.reduce((totals, item) => ({
    active: totals.active + (Number(item.value) || 0),
    planned: totals.planned + (Number(item.total) || 0),
  }), { active: 0, planned: 0 });
  const suspiciousIps = [...alerts]
    .filter((alert) => alert.sourceIp)
    .sort((left, right) => Number(right.risk || 0) - Number(left.risk || 0))
    .filter((alert, index, list) => list.findIndex((item) => item.sourceIp === alert.sourceIp) === index)
    .slice(0, 5);
  const sourceActivity = summarizeSourceActivity(events);
  const maxSourceCount = Math.max(1, ...sourceActivity.map((source) => source.count));
  const threatAnalysis = deriveThreatAnalysis(alerts, events);
  const {
    state: telemetryState,
    latestIngestion,
    ingestionAgeMinutes,
    activeSources,
    failedOutcomes,
  } = deriveTelemetryReadiness(events);
  const {
    state: queueState,
    criticalActiveAlerts,
    unassignedAlerts,
    escalatedAlerts,
    investigatingIncidents,
  } = deriveAnalystWorkload(activeAlerts, openIncidents);
  const summaryCards = [
    {
      label: "Total events",
      value: events.length.toLocaleString(),
      detail: rangeLabel,
      icon: Activity,
      route: SOC_ROUTES.eventLogs,
      tone: "info",
    },
    {
      label: "Critical alerts",
      value: criticalActiveAlerts.toLocaleString(),
      detail: unassignedAlerts ? `${unassignedAlerts.toLocaleString()} unassigned` : "Queue assigned",
      icon: ShieldAlert,
      route: SOC_ROUTES.alerts,
      tone: criticalActiveAlerts ? "critical" : "success",
    },
    {
      label: "Threats contained",
      value: containedAlerts.toLocaleString(),
      detail: `${completedIncidents.toLocaleString()} incidents completed`,
      icon: CheckCircle2,
      route: SOC_ROUTES.incidents,
      tone: "success",
    },
    {
      label: "Active incidents",
      value: openIncidents.length.toLocaleString(),
      detail: `${investigatingIncidents.toLocaleString()} investigating`,
      icon: AlertTriangle,
      route: SOC_ROUTES.incidents,
      tone: openIncidents.length ? "warning" : "success",
    },
    {
      label: "Monitored sources",
      value: activeSources.toLocaleString(),
      detail: `${ipActivity.unique.toLocaleString()} unique IPs`,
      icon: Network,
      route: SOC_ROUTES.eventLogs,
      tone: "teal",
    },
    {
      label: "Security posture",
      value: securityGrade.grade,
      detail: `${securityGrade.score}/100 · ${securityGrade.score >= 80 ? "Stable" : securityGrade.score >= 60 ? "Elevated risk" : "Review now"}`,
      icon: ShieldCheck,
      route: SOC_ROUTES.alerts,
      tone: securityGrade.tone,
    },
  ];

  function openThreatEvidence() {
    if (threatAnalysis.alertId) {
      setSelectedAlertId(threatAnalysis.alertId);
      navigate(SOC_ROUTES.alerts);
      return;
    }
    navigate(SOC_ROUTES.eventLogs);
  }

  return (
    <>
      <PageHeader
        title="Security overview"
        description={`Operational posture across connected sources · ${rangeLabel.toLowerCase()}.`}
        actions={(
          <button className="soc-button secondary dashboard-ai-action" type="button" onClick={() => navigate(SOC_ROUTES.aiAnalysis)}>
            AI analysis <ArrowRight size={15} />
          </button>
        )}
      />

      <section className="dashboard-summary-strip" aria-label="Security posture summary">
        {summaryCards.map((card) => (
          <DashboardSummaryCard
            key={card.label}
            {...card}
            onClick={() => navigate(card.route)}
          />
        ))}
      </section>

      <section className="dashboard-analytics-grid" aria-label="Security analytics">
        <Panel
          className="dashboard-events-panel"
          title="Events Over Time"
          subtitle={`${rangeLabel} · ${events.length.toLocaleString()} records received`}
          actions={(
            <label className="dashboard-chart-range">
              <span className="sr-only">Events chart time range</span>
              <select value={globalTimeRange} onChange={(event) => setGlobalTimeRange(event.target.value)}>
                {Object.entries(TIME_RANGE_LABELS).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
              </select>
            </label>
          )}
        >
          <LineAreaChart
            values={ingestion.values}
            labels={ingestion.labels}
            title={`Events ingested during ${rangeLabel.toLowerCase()}`}
          />
        </Panel>
        <Panel className="dashboard-severity-panel" title="Events by severity" subtitle={`${alerts.length.toLocaleString()} alert-linked events`}>
          <DonutChart segments={severity} totalLabel="alerts" />
          <div className="dashboard-severity-footer">
            <button className="soc-text-button" type="button" onClick={() => navigate(SOC_ROUTES.alerts)}>
              Review severity queue <ArrowRight size={13} />
            </button>
          </div>
        </Panel>
        <Panel className="dashboard-top-sources-panel" title="Top sources" subtitle={`By event count · ${rangeLabel.toLowerCase()}`}>
          {sourceActivity.length ? (
            <ol className="dashboard-source-list">
              {sourceActivity.map((source) => (
                <li key={source.sourceIp}>
                  <div>
                    <span className="dashboard-source-identity">
                      <span className="source-location-flag" role="img" aria-label={source.location.label} title={source.location.label}>{source.location.flag}</span>
                      <strong>{source.sourceIp}</strong>
                    </span>
                    <span>{source.count.toLocaleString()}</span>
                  </div>
                  <div className="dashboard-source-track" aria-label={`${source.sourceIp}: ${source.count} events`}>
                    <span style={{ width: `${(source.count / maxSourceCount) * 100}%` }} />
                  </div>
                  <small>{source.source} · {source.location.label}</small>
                </li>
              ))}
            </ol>
          ) : (
            <p className="empty-inline">No source addresses are available in this time range.</p>
          )}
          <button className="soc-text-button" type="button" onClick={() => navigate(SOC_ROUTES.eventLogs)}>
            View all event sources <ArrowRight size={13} />
          </button>
        </Panel>
        <Panel
          className="dashboard-severity-volume-panel"
          title="Alert volume by severity"
          subtitle={`${rangeLabel} · ${alerts.length.toLocaleString()} detections`}
          actions={(
            <div className="severity-chart-legend" aria-label="Severity series">
              {STACKED_SEVERITY_SERIES.slice().reverse().map((item) => (
                <span key={item.key}><i style={{ background: item.color }} />{item.label}</span>
              ))}
            </div>
          )}
        >
          <StackedBarChart
            buckets={severityBuckets}
            series={STACKED_SEVERITY_SERIES}
            title={`Alert volume by severity during ${rangeLabel.toLowerCase()}`}
          />
        </Panel>
      </section>

      <section className="dashboard-threat-grid" aria-label="Threat intelligence and detection coverage">
        <article className="dashboard-threat-card" data-threat-state={threatAnalysis.state} data-severity={threatAnalysis.severity}>
          <header>
            <span className="dashboard-threat-icon"><ShieldAlert size={20} aria-hidden="true" /></span>
            <div><strong>Threat analysis</strong><small>Evidence-backed priority finding</small></div>
            <SeverityBadge severity={threatAnalysis.severity} />
          </header>
          <div className="dashboard-threat-content">
            <span>{threatAnalysis.category}</span>
            <h2>{threatAnalysis.title}</h2>
            <p>{threatAnalysis.description}</p>
          </div>
          <dl className="dashboard-threat-metadata">
            <div><dt>User</dt><dd>{threatAnalysis.user}</dd></div>
            <div><dt>Source IP</dt><dd className="mono">{threatAnalysis.sourceIp}</dd></div>
            <div><dt>Window</dt><dd>{threatAnalysis.windowLabel}</dd></div>
            <div><dt>Evidence</dt><dd>{threatAnalysis.evidenceCount.toLocaleString()} records</dd></div>
          </dl>
          <footer>
            <button className="soc-button primary compact" type="button" onClick={openThreatEvidence}>
              {threatAnalysis.alertId ? "Review alert" : "Review evidence"} <ArrowRight size={14} />
            </button>
            <button className="soc-button secondary compact" type="button" onClick={() => navigate(SOC_ROUTES.aiAnalysis)}>
              Analyze with AI
            </button>
            <span>{threatAnalysis.ruleId}</span>
          </footer>
        </article>

        <Panel title="Detection coverage" subtitle="MITRE ATT&CK tactics">
          <CoverageBars items={coverageItems} />
          <button className="soc-text-button" type="button" onClick={() => navigate(SOC_ROUTES.threatDetection)}>
            {coverageTotals.active} of {coverageTotals.planned} planned rules active <ExternalLink size={13} />
          </button>
        </Panel>
      </section>

      <section className="dashboard-readiness-grid" aria-label="SOC operational readiness">
        <article className="readiness-card" data-tone={telemetryState.tone}>
          <header>
            <span><Activity size={18} /></span>
            <div><strong>Telemetry readiness</strong><small>Freshness and normalization inputs</small></div>
            <b className="readiness-state"><i aria-hidden="true" />{telemetryState.label}</b>
          </header>
          <div className="readiness-primary">
            <strong>{latestIngestion === null ? "Awaiting data" : formatTimestamp(latestIngestion)}</strong>
            <span>{latestIngestion === null ? "Upload or connect an event source to begin monitoring." : ingestionAgeMinutes < 1 ? "Latest batch received less than a minute ago" : `Latest batch received ${ingestionAgeMinutes.toLocaleString()} minutes ago`}</span>
          </div>
          <dl className="readiness-metrics">
            <div><dt>Active sources</dt><dd>{activeSources.toLocaleString()}</dd></div>
            <div><dt>Records received</dt><dd>{events.length.toLocaleString()}</dd></div>
            <div><dt>Failed outcomes</dt><dd>{failedOutcomes.toLocaleString()}</dd></div>
          </dl>
          <button className="soc-text-button" type="button" onClick={() => navigate(SOC_ROUTES.eventLogs)}>Inspect telemetry <ArrowRight size={13} /></button>
        </article>

        <article className="readiness-card" data-tone={queueState.tone}>
          <header>
            <span><UsersRound size={18} /></span>
            <div><strong>Analyst workload</strong><small>Ownership and response pressure</small></div>
            <b className="readiness-state"><i aria-hidden="true" />{queueState.label}</b>
          </header>
          <div className="readiness-primary">
            <strong>{unassignedAlerts ? `${unassignedAlerts.toLocaleString()} need ownership` : "Queue assigned"}</strong>
            <span>{criticalActiveAlerts ? `${criticalActiveAlerts.toLocaleString()} active critical alert${criticalActiveAlerts === 1 ? "" : "s"} should be reviewed first.` : "No active critical alerts are waiting in this period."}</span>
          </div>
          <dl className="readiness-metrics">
            <div><dt>Critical active</dt><dd>{criticalActiveAlerts.toLocaleString()}</dd></div>
            <div><dt>Escalated alerts</dt><dd>{escalatedAlerts.toLocaleString()}</dd></div>
            <div><dt>Investigations</dt><dd>{investigatingIncidents.toLocaleString()}</dd></div>
          </dl>
          <button className="soc-text-button" type="button" onClick={() => navigate(SOC_ROUTES.alerts)}>Open analyst queue <ArrowRight size={13} /></button>
        </article>
      </section>

      <section className="soc-grid dashboard-bottom" aria-label="Recent detection activity">
        <Panel
          className="span-2"
          title="Recent alerts"
          subtitle={rangeLabel}
          actions={<button className="soc-button secondary compact" type="button" onClick={() => navigate(SOC_ROUTES.alerts)}>View all</button>}
        >
          <div className="soc-table-scroll" role="region" aria-label="Scrollable recent alerts" tabIndex="0">
            <table className="soc-table">
              <thead><tr><th>Severity</th><th>Alert</th><th>Source</th><th>Risk</th><th>Status</th></tr></thead>
              <tbody>
                {alerts.slice(0, 5).map((alert) => (
                  <tr
                    key={alert.id}
                    tabIndex="0"
                    onClick={() => { setSelectedAlertId(alert.id); navigate(SOC_ROUTES.alerts); }}
                    onKeyDown={(event) => {
                      if (event.key === "Enter" || event.key === " ") {
                        event.preventDefault();
                        setSelectedAlertId(alert.id);
                        navigate(SOC_ROUTES.alerts);
                      }
                    }}
                  >
                    <td><SeverityBadge severity={alert.severity} /></td>
                    <td><strong>{alert.title}</strong><small>{alert.ruleId} · {alert.ruleName}</small></td>
                    <td className="mono">{alert.sourceIp}</td>
                    <td className="mono">{alert.risk}</td>
                    <td><StatusBadge status={alert.status} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
            {!alerts.length && <div className="table-empty"><strong>No recent alerts</strong><span>No detections fall inside the selected time range.</span></div>}
          </div>
        </Panel>
        <Panel title="Suspicious IPs" subtitle={`Highest-risk sources · ${rangeLabel.toLowerCase()}`}>
          <ul className="ip-list">
            {suspiciousIps.map((alert) => (
              <li key={alert.sourceIp}><div><strong>{alert.sourceIp}</strong><small>{alert.risk} risk · {alert.source}</small></div><StatusBadge status={alert.status} /></li>
            ))}
          </ul>
          {!suspiciousIps.length && <p className="empty-inline">No alert source addresses fall inside the selected time range.</p>}
        </Panel>
      </section>
    </>
  );
}
