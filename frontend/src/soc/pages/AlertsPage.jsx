import { useEffect, useMemo, useState } from "react";
import { AlertTriangle, ArrowUpRight, BookOpenCheck, CheckCircle2, Clock3, GitBranch, MessageSquareText, RefreshCw, Save, Search, Send, ShieldPlus, X } from "lucide-react";
import { SOC_ROUTES } from "../../hooks/useAuthRoute";
import { useSocWorkspace } from "../context/SocWorkspaceContext";
import { usePersistedInvestigation } from "../hooks/usePersistedInvestigation";
import { socRepository } from "../services/socRepository";
import { formatTimestamp } from "../utils/eventUtils";
import { nextIncidentId } from "../utils/recordIds";
import { paginateRecords } from "../utils/pagination";
import { isTerminalIncidentStatus } from "../utils/incidentWorkflow";
import { getAlertRecommendations, getIncidentActionLabel, incidentMatchesAlert } from "../utils/alertRecommendations";
import { evidenceEntries } from "../utils/ruleConfig";
import { formatEvidenceValue, investigationHistoryForIncident, normalizedEvidenceRows, rawEvidenceRows, relatedAlertsForAlert } from "../utils/investigationViews";
import {
  ErrorState,
  InlineNotice,
  LoadingState,
  PageHeader,
  Panel,
  RiskMeter,
  SeverityBadge,
  StatCard,
  StatusBadge,
  TablePagination,
  ValidationMessage,
} from "../components/Ui";

const ALERT_STATUSES = ["new", "triaging", "investigating", "acknowledged", "escalated", "contained", "resolved"];
const API_ALERT_STATUSES = ["new", "investigating", "escalated", "resolved", "false positive", "legacy closed"];
const PAGE_SIZE = 10;
const EVIDENCE_PAGE_SIZE = 4;

function formatAlertTimeRange(alert) {
  const start = formatTimestamp(alert.firstSeen || alert.observedAt || alert.createdAt);
  const end = formatTimestamp(alert.lastSeen || alert.firstSeen || alert.observedAt || alert.createdAt);
  if (start === end) return `${start} · single observation`;
  return `${start} – ${end}`;
}

function minutesLabel(seconds) {
  const minutes = Math.round(Number(seconds) / 60);
  return minutes >= 60 ? `${Math.round(minutes / 60)}h` : `${minutes}m`;
}

/** Maps a rule's actions.<key> outcome (set by the backend after the alert
 * fired) to an icon, tone, and human-readable line for the alert detail rail. */
function describeActionResult(key, result) {
  if (!result || typeof result !== "object") return null;

  if (key === "notify_slack") {
    if (result.status === "sent") {
      return { tone: "ok", icon: Send, text: `Slack notification sent${result.status_code ? ` (HTTP ${result.status_code})` : ""}.` };
    }
    if (result.status === "skipped") {
      return { tone: "muted", icon: Send, text: "Slack notification skipped — no webhook configured." };
    }
    return { tone: "error", icon: AlertTriangle, text: `Slack notification failed${result.error ? `: ${result.error}` : "."}` };
  }

  if (key === "auto_incident") {
    if (result.status === "created") {
      return { tone: "ok", icon: ShieldPlus, text: `Auto-created incident #${result.incident_id}.` };
    }
    if (result.status === "already_exists") {
      return { tone: "muted", icon: ShieldPlus, text: `Incident #${result.incident_id} already exists for this alert.` };
    }
    if (result.status === "threshold_not_met") {
      return {
        tone: "muted",
        icon: Clock3,
        text: `Auto-incident threshold not met (needs ${result.threshold_count} events within ${minutesLabel(result.threshold_window_seconds)}).`,
      };
    }
    return null;
  }

  if (key === "suggest_playbook") {
    if (result.status === "linked") {
      return { tone: "ok", icon: BookOpenCheck, text: `Playbook ${result.playbook_id} linked.` };
    }
    return null;
  }

  return null;
}

export default function AlertsPage({ navigate }) {
  const {
    timeFilteredAlerts: alerts,
    alerts: allAlerts,
    canWrite,
    currentActor,
    incidents,
    notes,
    events,
    detectionRules,
    mutation,
    repositoryMode,
    resources,
    refresh,
    updateAlertStatus,
    createIncident,
    addNote,
    selectedAlertId,
    setSelectedAlertId,
    setSelectedIncidentId,
    setGlobalTimeRange,
  } = useSocWorkspace();
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const [source, setSource] = useState("");
  const [page, setPage] = useState(1);
  const [noteComposerOpen, setNoteComposerOpen] = useState(false);
  const [noteComment, setNoteComment] = useState("");
  const [noteError, setNoteError] = useState("");
  const [evidencePage, setEvidencePage] = useState(1);
  const [noteSaving, setNoteSaving] = useState(false);
  const loading = resources.alerts.loading || resources.events.loading;
  const error = resources.alerts.error || resources.events.error;

  const availableStatuses = repositoryMode === "api" ? API_ALERT_STATUSES : ALERT_STATUSES;
  const sources = useMemo(() => [...new Set(alerts.map((alert) => alert.source).filter(Boolean))].sort(), [alerts]);
  const filtered = useMemo(() => alerts.filter((alert) => {
    const searchText = `${alert.id} ${alert.title} ${alert.sourceIp} ${alert.ruleId} ${alert.ruleName} ${alert.assignee}`.toLowerCase();
    return (
      (!query || searchText.includes(query.toLowerCase())) &&
      (!severity || alert.severity === severity) &&
      (!status || alert.status === status) &&
      (!source || alert.source === source)
    );
  }), [alerts, query, severity, source, status]);
  const pagination = useMemo(() => paginateRecords(filtered, page, PAGE_SIZE), [filtered, page]);
  const pageAlerts = pagination.items;
  // The detail card follows the analyst's explicit workspace selection, not
  // the visible table page. Pagination and route changes therefore never
  // discard the record being investigated.
  const cachedSelected = allAlerts.find((alert) => alert.id === selectedAlertId) || null;
  const persisted = usePersistedInvestigation("alert", cachedSelected || { id: selectedAlertId }, repositoryMode, mutation.message);
  const selected = cachedSelected || persisted.data?.alert || null;
  const permittedStatuses = repositoryMode === "api" ? [...new Set([selected?.status,
    ...(persisted.data?.allowedStates || []).map((state) => state.toLowerCase().replaceAll("_", " "))])].filter(Boolean) : availableStatuses;
  const rule = selected ? detectionRules[selected.ruleId] : null;
  const evidence = repositoryMode === "api" ? persisted.data?.events || [] : selected ? events.filter((event) => selected.evidenceIds.includes(event.id)) : [];
  const evidencePagination = useMemo(() => paginateRecords(evidence, evidencePage, EVIDENCE_PAGE_SIZE), [evidence, evidencePage]);
  const relatedActivity = repositoryMode === "api" ? persisted.data?.related || [] : relatedAlertsForAlert(selected, allAlerts, events);
  const linkedIncident = selected ? incidents.find((incident) => incidentMatchesAlert(incident, selected)) : null;
  const investigationHistory = repositoryMode === "api" ? persisted.data?.history || [] : investigationHistoryForIncident(linkedIncident, notes);
  const recommendations = selected ? getAlertRecommendations(selected) : [];
  const linkedIncidentIsTerminal = linkedIncident ? isTerminalIncidentStatus(linkedIncident.status) : false;
  const incidentActionLabel = getIncidentActionLabel(linkedIncident, selected?.severity);

  useEffect(() => {
    setPage(1);
  }, [query, severity, source, status]);

  useEffect(() => {
    setEvidencePage(1);
  }, [selected?.id]);

  if (loading) return <LoadingState label="Synchronizing active alerts and matched evidence…" />;
  if (error) return <ErrorState message={error} onRetry={() => Promise.all([refresh("alerts"), refresh("events")])} />;

  async function promoteToIncident() {
    if (!selected) return;
    if (linkedIncident) {
      setSelectedIncidentId(linkedIncident.id);
      if (!linkedIncidentIsTerminal) setGlobalTimeRange("all");
      navigate(SOC_ROUTES.incidents);
      return;
    }

    const created = await createIncident({
      id: nextIncidentId(incidents),
      title: selected.title,
      owner: currentActor,
      priority: selected.severity,
      status: "open",
      updated: "Just now",
      sla: selected.severity === "critical" ? "5m acknowledge target" : "30m acknowledge target",
      summary: selected.summary,
      eventIds: selected.evidenceIds,
      sourceAlertId: selected.sourceAlertId,
    });
    if (created) {
      setSelectedIncidentId(created.id);
      navigate(SOC_ROUTES.incidents);
    }
  }

  function openNoteComposer() {
    setNoteComment("");
    setNoteError("");
    setNoteComposerOpen(true);
  }

  async function saveAlertNote(event) {
    event.preventDefault();
    if (!selected || mutation.loading || noteSaving) return;
    const comment = noteComment.trim();
    if (comment.length < 12) {
      setNoteError("Add at least 12 characters of analyst context.");
      return;
    }
    if (repositoryMode === "api") {
      setNoteSaving(true);
      try {
        await socRepository.addInvestigationNote(selected.id, comment, persisted.data?.alert.version);
        await refresh("alerts");
        setNoteComposerOpen(false);
      } catch (error) { setNoteError(error.message); }
      finally { setNoteSaving(false); }
      return;
    }

    let targetIncident = linkedIncident;
    if (!targetIncident) {
      targetIncident = await createIncident({
        id: nextIncidentId(incidents),
        title: selected.title,
        owner: currentActor,
        priority: selected.severity,
        status: "open",
        updated: "Just now",
        sla: selected.severity === "critical" ? "5m acknowledge target" : "30m acknowledge target",
        summary: selected.summary,
        eventIds: selected.evidenceIds,
        sourceAlertId: selected.sourceAlertId,
      });
      if (!targetIncident) return;
    }

    const context = [
      comment,
      "",
      `Alert: ${selected.id} — ${selected.title}`,
      `Source: ${selected.sourceIp} · ${selected.source}`,
      `Rule: ${selected.ruleId} · ${selected.ruleName}`,
      `Evidence: ${selected.evidenceIds.length} matched event${selected.evidenceIds.length === 1 ? "" : "s"}`,
    ].join("\n");
    const saved = await addNote({
      title: `${selected.id} triage note`,
      body: context,
      tags: ["alert-triage", String(selected.ruleId || "detection").toLowerCase()],
      linkedType: "incident",
      linkedId: targetIncident.id,
    });
    if (saved) {
      setNoteComposerOpen(false);
      navigate(SOC_ROUTES.analystNotes);
    }
  }

  return (
    <>
      <PageHeader
        title="Alerts"
        description="Triage synchronized detections, inspect matched logs, and review rule context before escalation."
        actions={<button className="soc-button secondary" type="button" disabled={mutation.loading} onClick={() => Promise.all([refresh("alerts"), refresh("events")])}><RefreshCw size={15} />Refresh alerts</button>}
      />

      <div className="soc-stats-grid">
        <StatCard label="Active alerts" value={alerts.filter((alert) => !["contained", "resolved"].includes(alert.status)).length} trend={`${alerts.filter((alert) => alert.status === "new").length} awaiting first review`} />
        <StatCard label="Critical" value={alerts.filter((alert) => alert.severity === "critical" && alert.status !== "resolved").length} trend="Immediate triage target" tone="critical" />
        <StatCard label="Investigating" value={alerts.filter((alert) => ["triaging", "investigating"].includes(alert.status)).length} trend="Assigned analyst work" />
        <StatCard label="Contained or resolved" value={alerts.filter((alert) => ["contained", "resolved"].includes(alert.status)).length} trend="Current dataset" tone="success" />
      </div>

      <section className="filter-bar alerts-filter-bar" aria-label="Alert filters">
        <label className="filter-search"><Search size={16} /><span className="sr-only">Search alerts</span><input type="search" maxLength="200" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search alerts, IPs, rules…" /></label>
        <label><span className="sr-only">Severity</span><select value={severity} onChange={(event) => setSeverity(event.target.value)}><option value="">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></label>
        <label><span className="sr-only">Status</span><select value={status} onChange={(event) => setStatus(event.target.value)}><option value="">All statuses</option>{availableStatuses.map((item) => <option key={item} value={item}>{item}</option>)}</select></label>
        <label><span className="sr-only">Source</span><select value={source} onChange={(event) => setSource(event.target.value)}><option value="">All sources</option>{sources.map((item) => <option key={item}>{item}</option>)}</select></label>
        <button className="soc-button secondary" type="button" onClick={() => { setQuery(""); setSeverity(""); setStatus(""); setSource(""); }}>Clear filters</button>
      </section>

      <div className="alerts-workspace">
        <Panel title="Alert queue" subtitle={`${filtered.length} of ${alerts.length} detections${filtered.length > PAGE_SIZE ? ` · page ${pagination.page} of ${pagination.pageCount}` : ""}`}>
          <div className={`soc-table-scroll alerts-table-wrap${filtered.length > PAGE_SIZE ? " with-pagination" : ""}`} role="region" aria-label="Scrollable alert queue" tabIndex="0">
            <table className="soc-table alerts-table">
              <thead><tr><th>Alert</th><th>Severity</th><th>Source</th><th>Assignee</th><th>Status</th><th>Observed</th></tr></thead>
              <tbody>
                {pageAlerts.map((alert) => (
                  <tr key={alert.id} className={selected?.id === alert.id ? "selected" : ""} onClick={() => setSelectedAlertId(alert.id)} tabIndex="0" onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); setSelectedAlertId(alert.id); } }}>
                    <td><strong>{alert.title}</strong><small>{alert.id} · {alert.ruleId}</small></td>
                    <td><SeverityBadge severity={alert.severity} /></td>
                    <td><span className="mono">{alert.sourceIp}</span><small>{alert.source}</small></td>
                    <td>{alert.assignee}</td>
                    <td><StatusBadge status={alert.status} /></td>
                    <td>{formatTimestamp(alert.observedAt || alert.createdAt)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {!filtered.length && <div className="table-empty"><Search size={22} /><strong>No alerts match these filters</strong><span>Clear or adjust filters to restore the queue.</span></div>}
          </div>
          <TablePagination label="alerts" page={pagination.page} pageSize={PAGE_SIZE} totalItems={filtered.length} onPageChange={setPage} />
        </Panel>

        <aside className="alert-detail-column" aria-label="Scrollable alert details" tabIndex="0">
          {selected ? (
            <>
              <Panel title={selected.id} subtitle={formatTimestamp(selected.observedAt || selected.createdAt)} actions={<SeverityBadge severity={selected.severity} />}>
                <div className="alert-detail-summary">
                  <h3>{selected.title}</h3>
                  <div className="alert-reason"><span>Reason</span><p>{selected.reason || selected.summary}</p></div>
                  <RiskMeter value={selected.risk} />
                  <label className="status-control"><span>Alert status</span><select value={selected.status} disabled={mutation.loading || !canWrite || (repositoryMode === "api" && (persisted.loading || permittedStatuses.length <= 1))} title={!canWrite ? "Viewer access is read-only." : undefined} onChange={(event) => updateAlertStatus(selected.id, event.target.value)}>{permittedStatuses.map((item) => <option key={item} value={item}>{item}</option>)}</select></label>
                  <dl className="alert-context-list">
                    <div><dt>Severity</dt><dd><SeverityBadge severity={selected.severity} /></dd></div>
                    <div><dt>Affected user</dt><dd className="mono">{selected.user || "Unknown"}</dd></div>
                    <div><dt>Detection rule</dt><dd>{selected.ruleId} · {selected.ruleName}</dd></div>
                    <div><dt>Time range</dt><dd>{formatAlertTimeRange(selected)}</dd></div>
                    <div><dt>Assignee</dt><dd>{selected.assignee}</dd></div>
                    <div><dt>Source</dt><dd>{selected.source}</dd></div>
                    <div><dt>Source IP</dt><dd className="mono">{selected.sourceIp}</dd></div>
                    {selected.hostname && <div><dt>Host</dt><dd className="mono">{selected.hostname}</dd></div>}
                    {selected.mitreTechnique && <div><dt>ATT&amp;CK</dt><dd>{selected.mitreTechnique}</dd></div>}
                    {selected.confidence !== null && <div><dt>Confidence</dt><dd>{selected.confidence}%</dd></div>}
                  </dl>
                  {evidenceEntries(selected.evidence).length > 0 && (
                    <div className="alert-evidence-detail">
                      <span>Detection evidence</span>
                      <dl>
                        {evidenceEntries(selected.evidence).map((row) => (
                          <div key={row.key}><dt>{row.label}</dt><dd>{row.value}</dd></div>
                        ))}
                      </dl>
                    </div>
                  )}
                  <button className={`soc-button ${linkedIncident ? "secondary" : "primary"} full`} type="button" disabled={(!linkedIncident && !canWrite) || mutation.loading || (repositoryMode === "api" && !selected.sourceAlertId && !linkedIncident)} onClick={promoteToIncident}><ShieldPlus size={15} />{incidentActionLabel}</button>
                  <button className="soc-button secondary full" type="button" disabled={!canWrite || mutation.loading} onClick={openNoteComposer}><BookOpenCheck size={15} />Add analyst note</button>
                </div>
              </Panel>

              <Panel title="Matched log evidence" subtitle={`${evidence.length} normalized record${evidence.length === 1 ? "" : "s"}${evidence.length > EVIDENCE_PAGE_SIZE ? ` · page ${evidencePagination.page} of ${evidencePagination.pageCount}` : ""}`}>
                {persisted.loading && <p>Loading original evidence…</p>}
                {persisted.error && <p role="alert">{persisted.error}</p>}
                {persisted.data?.completeness?.complete === false && <p role="status">Some historical source events are unavailable. Available evidence is shown below.</p>}
                <div className="evidence-cards">
                  {evidencePagination.items.map((event) => (
                    <article key={event.id}>
                      <header><strong className="mono">{event.id}</strong><StatusBadge status={event.status} /></header>
                      <div className="evidence-field-groups">
                        <section>
                          <h4>Normalized fields</h4>
                          <dl>
                            {normalizedEvidenceRows(event).map(([key, value]) => (
                              <div key={key}><dt>{key}</dt><dd>{formatEvidenceValue(value)}</dd></div>
                            ))}
                          </dl>
                        </section>
                        <section>
                          <h4>Preserved raw evidence</h4>
                          <dl>
                            {rawEvidenceRows(selected, event).map(([key, value]) => (
                              <div key={key}><dt>{key}</dt><dd>{formatEvidenceValue(value)}</dd></div>
                            ))}
                          </dl>
                          {!rawEvidenceRows(selected, event).length && <p className="empty-inline">No raw evidence fields were supplied by the source API.</p>}
                        </section>
                      </div>
                    </article>
                  ))}
                  {!evidence.length && <p className="empty-inline">No normalized log evidence is linked to this alert yet.</p>}
                </div>
                <TablePagination label="evidence records" page={evidencePagination.page} pageSize={EVIDENCE_PAGE_SIZE} totalItems={evidence.length} onPageChange={setEvidencePage} />
                <button className="soc-text-button" type="button" onClick={() => navigate(SOC_ROUTES.eventLogs)}>Open complete event log <ArrowUpRight size={13} /></button>
              </Panel>

              <Panel title="Correlated activity" subtitle={repositoryMode === "api" ? "Recorded correlation groups and their rule context" : "Related activity in the sample dataset"}>
                {persisted.data?.groups.map((group) => <article key={group.id}><strong>Group {group.id}</strong><p>{group.reason}</p><details><summary>Rule context when detected</summary><pre>{JSON.stringify(group.ruleContext, null, 2)}</pre></details></article>)}
                <div className="correlation-list">
                  {relatedActivity.map((item) => (
                    <article key={`${item.groupId || "sample"}-${item.alert.id}`}>
                      <header><span><GitBranch size={14} />{item.reason}</span><SeverityBadge severity={item.alert.severity} /></header>
                      <strong>{item.alert.id} · {item.alert.title}</strong>
                      <dl>
                        <div><dt>Grouping entity</dt><dd className="mono">{item.groupingEntity}</dd></div>
                        <div><dt>Time window</dt><dd>{item.timeWindow}</dd></div>
                        <div><dt>Linked events</dt><dd>{item.linkedEventCount ?? item.linkedEvents.length}</dd></div>
                      </dl>
                      <button className="soc-text-button" type="button" onClick={() => setSelectedAlertId(item.alert.id)}>Inspect related alert <ArrowUpRight size={13} /></button>
                    </article>
                  ))}
                  {!relatedActivity.length && <p className="empty-inline">No additional alert belongs to this alert's recorded correlation groups.</p>}
                </div>
              </Panel>

              <Panel title="Investigation history" subtitle={repositoryMode === "api" ? `${investigationHistory.length} recorded changes` : linkedIncident ? `${linkedIncident.id} · ${investigationHistory.length} timeline items` : "No incident has been opened yet"}>
                {linkedIncident || repositoryMode === "api" ? (
                  <ol className="timeline-list compact">
                    {investigationHistory.map((item) => (
                      <li key={item.id}><Clock3 size={16} /><div><strong>{item.title}</strong><span>{formatTimestamp(item.at)} · {item.detail}</span></div></li>
                    ))}
                  </ol>
                ) : (
                  <p className="empty-inline">Promote this alert or save an analyst note to begin investigation history.</p>
                )}
              </Panel>

              <Panel
                title="Recommended response actions"
                subtitle={selected.playbook?.id ? `${selected.playbook.id} · ${selected.playbook.title}` : recommendations.length ? `${recommendations.length} actions for this alert type` : "No predefined playbook available"}
              >
                {selected.playbook?.route && <button className="soc-text-button" type="button" onClick={() => navigate(selected.playbook.route)}>Open linked playbook <ArrowUpRight size={13} /></button>}
                {recommendations.length ? <ol className="alert-recommendations">{recommendations.map((recommendation) => <li key={recommendation}><CheckCircle2 size={15} /><span>{recommendation}</span></li>)}</ol> : <p className="empty-inline">No automated response recommendation is available. Refer the alert to the assigned analyst and follow the approved response playbook.</p>}
              </Panel>

              {Boolean(selected.actionResults && Object.keys(selected.actionResults).length) && (
                <Panel title="Rule actions" subtitle="What ran automatically when this alert fired">
                  <ul className="alert-action-results">
                    {Object.entries(selected.actionResults).map(([key, result]) => {
                      const described = describeActionResult(key, result);
                      if (!described) return null;
                      const Icon = described.icon;
                      return (
                        <li key={key} data-state={described.tone}>
                          <Icon size={14} aria-hidden="true" />
                          <span>{described.text}</span>
                        </li>
                      );
                    })}
                  </ul>
                </Panel>
              )}

              {/* Placeholder for a future ML anomaly-detection integration.
                  No backend field populates selected.mlInsight today, so
                  this panel never renders yet — it is ready to surface a
                  model's score and explanation the moment one exists. */}
              {Boolean(selected.mlInsight) && (
                <Panel title="ML anomaly insight" subtitle={selected.mlInsight.label || "Model-generated assessment"}>
                  {selected.mlInsight.score !== null && <RiskMeter value={selected.mlInsight.score} />}
                  {selected.mlInsight.explanation && <p className="alert-reason">{selected.mlInsight.explanation}</p>}
                  {Boolean(selected.mlInsight.contributingFactors.length) && (
                    <ul className="alert-recommendations">
                      {selected.mlInsight.contributingFactors.map((factor) => <li key={factor}><CheckCircle2 size={15} /><span>{factor}</span></li>)}
                    </ul>
                  )}
                </Panel>
              )}

              <Panel title="Detection rule" subtitle={rule ? `${rule.id} · version ${rule.version}` : selected.ruleId}>
                {rule ? <div className="rule-detail"><div className="rule-title-row"><h3>{rule.name}</h3><StatusBadge status={rule.status} /></div><p>{rule.description}</p><dl><div><dt>ATT&CK</dt><dd>{rule.technique}</dd></div><div><dt>Owner</dt><dd>{rule.owner}</dd></div><div><dt>Updated</dt><dd>{rule.lastUpdated}</dd></div></dl><code>{rule.query}</code></div> : <p className="empty-inline">Detection-rule details are not available for this alert.</p>}
              </Panel>
            </>
          ) : <div className="detail-placeholder"><Search size={24} /><strong>Select an alert</strong><span>Review evidence and detection logic before changing status.</span></div>}
        </aside>
      </div>

      {noteComposerOpen && selected && (
        <div className="soc-modal-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget && !mutation.loading) setNoteComposerOpen(false); }}>
          <section className="soc-modal alert-note-modal" role="dialog" aria-modal="true" aria-labelledby="alert-note-title">
            <header><div><h2 id="alert-note-title">Add alert triage note</h2><p>Save analyst context with the selected alert and its persisted investigation record.</p></div><button type="button" disabled={mutation.loading} onClick={() => setNoteComposerOpen(false)} aria-label="Close"><X size={18} /></button></header>
            <div className="alert-note-context"><span><MessageSquareText size={16} /></span><div><strong>{selected.id} · {selected.title}</strong><p>{selected.sourceIp} · {selected.ruleId} · {evidence.length} matched event{evidence.length === 1 ? "" : "s"}</p></div></div>
            {!linkedIncident && repositoryMode !== "api" && <InlineNotice tone="info" title="Investigation record required">Saving will first create an incident for this sample alert.</InlineNotice>}
            <form onSubmit={saveAlertNote} noValidate>
              <label className={noteError ? "has-error" : undefined}>Analyst comment<textarea value={noteComment} onChange={(event) => { setNoteComment(event.target.value); if (noteError) setNoteError(""); }} maxLength="1200" rows="6" autoFocus placeholder="Record what you verified, why it matters, and the recommended next step…" aria-invalid={Boolean(noteError)} aria-describedby={noteError ? "alert-note-comment-error" : undefined} /><ValidationMessage id="alert-note-comment-error">{noteError}</ValidationMessage></label>
              <div className="soc-modal-actions"><button className="soc-button secondary" type="button" disabled={mutation.loading || noteSaving} onClick={() => setNoteComposerOpen(false)}>Cancel</button><button className="soc-button primary" type="submit" disabled={mutation.loading || noteSaving || !noteComment.trim()}><Save size={15} />{mutation.loading || noteSaving ? "Saving…" : repositoryMode === "api" || linkedIncident ? "Save note" : "Create incident & save"}</button></div>
            </form>
          </section>
        </div>
      )}
    </>
  );
}
