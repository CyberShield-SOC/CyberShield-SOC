import { useEffect, useMemo, useRef, useState } from "react";
import {
  Bot,
  Check,
  ChevronDown,
  CircleCheckBig,
  CircleX,
  FileSearch,
  MessageSquareText,
  PlayCircle,
  Search,
  ShieldPlus,
  Sparkles,
  Workflow,
  Zap,
} from "lucide-react";
import { SOC_ROUTES } from "../../hooks/useAuthRoute";
import { useSocWorkspace } from "../context/SocWorkspaceContext";
import { socRepository } from "../services/socRepository";
import { formatTimestamp } from "../utils/eventUtils";
import { nextIncidentId } from "../utils/recordIds";
import { filterAlertsForPicker, isQuickResolvableAlert } from "../utils/workspaceSelectors";
import { incidentMatchesAlert } from "../utils/alertRecommendations";
import { isTerminalIncidentStatus } from "../utils/incidentWorkflow";
import { ErrorState, InlineNotice, PageHeader, Panel, RiskMeter, SeverityBadge, StatusBadge, ValidationMessage } from "../components/Ui";

const MAX_INCIDENT_NOTES = 5;
const CHECKLIST = [
  "Validate source and affected identity",
  "Review matched evidence and detection logic",
  "Record the response decision",
  "Confirm containment or escalation",
];

function SearchableAlertPicker({ alerts, onChange, value }) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const pickerRef = useRef(null);
  const searchRef = useRef(null);
  const selected = alerts.find((alert) => alert.id === value) || null;
  const filteredAlerts = useMemo(() => filterAlertsForPicker(alerts, query), [alerts, query]);

  useEffect(() => {
    if (!open) return undefined;
    searchRef.current?.focus();

    function closeOnOutsideClick(event) {
      if (!pickerRef.current?.contains(event.target)) setOpen(false);
    }

    function closeOnEscape(event) {
      if (event.key === "Escape") setOpen(false);
    }

    document.addEventListener("mousedown", closeOnOutsideClick);
    document.addEventListener("keydown", closeOnEscape);
    return () => {
      document.removeEventListener("mousedown", closeOnOutsideClick);
      document.removeEventListener("keydown", closeOnEscape);
    };
  }, [open]);

  function chooseAlert(alertId) {
    onChange(alertId);
    setQuery("");
    setOpen(false);
  }

  return (
    <div className="quick-resolve-picker" ref={pickerRef}>
      <button
        className="quick-alert-picker-trigger"
        type="button"
        aria-haspopup="listbox"
        aria-expanded={open}
        onClick={() => setOpen((current) => !current)}
      >
        <Zap size={16} />
        <span><small>Active alert</small><strong>{selected ? `${selected.id} · ${selected.title}` : "Select an alert to investigate"}</strong></span>
        <ChevronDown size={16} aria-hidden="true" />
      </button>
      {open && (
        <div className="quick-alert-picker-popover">
          <label className="quick-alert-picker-search">
            <Search size={16} />
            <span className="sr-only">Search active alerts</span>
            <input
              ref={searchRef}
              type="search"
              maxLength="200"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search ID, title, IP, user, or rule…"
            />
          </label>
          <div className="quick-alert-picker-results" role="listbox" aria-label="Active alerts">
            {filteredAlerts.map((alert) => (
              <button
                key={alert.id}
                type="button"
                role="option"
                aria-selected={alert.id === value}
                onClick={() => chooseAlert(alert.id)}
              >
                <span><strong className="mono">{alert.id}</strong><SeverityBadge severity={alert.severity} /></span>
                <b>{alert.title}</b>
                <small>{alert.sourceIp} · {alert.ruleId} · {alert.status}</small>
              </button>
            ))}
            {!filteredAlerts.length && <p>No alerts match “{query.trim()}”.</p>}
          </div>
          <footer>{filteredAlerts.length} of {alerts.length} alerts</footer>
        </div>
      )}
    </div>
  );
}

export default function QuickResolvePage({ navigate }) {
  const {
    addNote,
    alerts,
    canWrite,
    currentActor,
    createIncident,
    detectionRules,
    events,
    incidents,
    mutation,
    notes,
    refresh,
    repositoryMode,
    resources,
    settings,
    setTrackingIncidentId,
    setSelectedIncidentId,
    selectedAlertId,
    setSelectedAlertId,
    updateAlertStatus,
    updateIncidentStatus,
  } = useSocWorkspace();
  const [note, setNote] = useState("");
  const [noteError, setNoteError] = useState("");
  const [workflowError, setWorkflowError] = useState("");
  const [analysis, setAnalysis] = useState(null);
  const [analysisError, setAnalysisError] = useState("");
  const [analyzing, setAnalyzing] = useState(false);
  const [checklistByAlert, setChecklistByAlert] = useState({});

  const selectableAlerts = useMemo(
    () => alerts.filter((alert) => isQuickResolvableAlert(alert, incidents)),
    [alerts, incidents],
  );
  const selectedAlert = selectableAlerts.find((alert) => alert.id === selectedAlertId) || null;
  const linkedIncident = selectedAlert ? incidents.find((incident) => incidentMatchesAlert(incident, selectedAlert)) : null;
  const evidence = selectedAlert ? events.filter((event) => selectedAlert.evidenceIds.includes(event.id)) : [];
  const rule = selectedAlert ? detectionRules[selectedAlert.ruleId] : null;
  const incidentNotes = linkedIncident ? notes.filter((item) => item.linkedType === "incident" && item.linkedId === linkedIncident.id && !item.archived) : [];
  const checkedSteps = selectedAlert ? checklistByAlert[selectedAlert.id] || [] : [];
  const loading = resources.alerts.loading || resources.events.loading || resources.incidents.loading || resources.notes.loading;
  const resourceError = resources.alerts.error || resources.events.error || resources.incidents.error || resources.notes.error;
  const aiEnabled = settings?.ai?.enabled !== false;

  useEffect(() => {
    setNote("");
    setNoteError("");
    setWorkflowError("");
    setAnalysis(null);
    setAnalysisError("");
  }, [selectedAlertId]);

  useEffect(() => {
    if (selectedAlertId && !selectedAlert) setSelectedAlertId(null);
  }, [selectedAlert, selectedAlertId, setSelectedAlertId]);

  function toggleChecklist(index, checked) {
    if (!selectedAlert) return;
    setChecklistByAlert((current) => {
      const next = new Set(current[selectedAlert.id] || []);
      if (checked) next.add(index); else next.delete(index);
      return { ...current, [selectedAlert.id]: [...next] };
    });
  }

  async function createFromAlert() {
    if (!selectedAlert || linkedIncident || mutation.loading) return;
    setWorkflowError("");
    if (repositoryMode === "api" && !selectedAlert.sourceAlertId) {
      setWorkflowError("This alert does not have the persisted source identifier required by the incident API.");
      return;
    }
    await createIncident({
      id: nextIncidentId(incidents),
      title: selectedAlert.title,
      owner: selectedAlert.assignee === "Unassigned" ? currentActor : selectedAlert.assignee,
      priority: selectedAlert.severity,
      status: "open",
      updated: "Just now",
      sla: selectedAlert.severity === "critical" ? "5m acknowledge target" : "30m acknowledge target",
      summary: selectedAlert.summary,
      eventIds: selectedAlert.evidenceIds,
      sourceAlertId: selectedAlert.sourceAlertId,
    });
  }

  async function startInvestigation() {
    if (!selectedAlert || !linkedIncident || mutation.loading) return;
    setWorkflowError("");
    if (!["investigating", "escalated", "resolved"].includes(selectedAlert.status)) {
      const updated = await updateAlertStatus(selectedAlert.id, "investigating");
      if (!updated) return;
    }
    if (linkedIncident.status !== "investigating" && !isTerminalIncidentStatus(linkedIncident.status)) {
      await updateIncidentStatus(linkedIncident.id, "investigating");
    }
  }

  async function resolveInvestigation() {
    if (!selectedAlert || !linkedIncident || mutation.loading) return;
    setWorkflowError("");
    if (selectedAlert.status !== "resolved") {
      const updated = await updateAlertStatus(selectedAlert.id, "resolved");
      if (!updated) return;
    }
    if (!isTerminalIncidentStatus(linkedIncident.status)) {
      await updateIncidentStatus(linkedIncident.id, "resolved");
    }
  }

  async function markFalsePositive() {
    if (!selectedAlert || !linkedIncident || mutation.loading) return;
    setWorkflowError("");
    if (selectedAlert.status !== "resolved") {
      const updated = await updateAlertStatus(selectedAlert.id, "resolved");
      if (!updated) return;
    }
    await updateIncidentStatus(linkedIncident.id, "false positive");
  }

  async function saveNote(event) {
    event.preventDefault();
    if (!linkedIncident || mutation.loading) return;
    if (incidentNotes.length >= MAX_INCIDENT_NOTES) {
      setNoteError("This incident already has the maximum of 5 analyst notes.");
      return;
    }
    const body = note.trim();
    if (body.length < 12) {
      setNoteError("Add at least 12 characters of investigation context.");
      return;
    }
    const saved = await addNote({
      title: `${selectedAlert.id} quick resolve update`,
      body,
      tags: ["quick-resolve", String(selectedAlert.ruleId || "detection").toLowerCase()],
      linkedType: "incident",
      linkedId: linkedIncident.id,
    });
    if (saved) setNote("");
  }

  async function runAnalysis() {
    if (!selectedAlert || analyzing || !aiEnabled) return;
    setAnalyzing(true);
    setAnalysisError("");
    try {
      setAnalysis(await socRepository.runAiAnalysis({ subject: `${selectedAlert.id} · ${selectedAlert.title}` }));
    } catch {
      setAnalysisError("The analysis service is unavailable. Evidence and manual workflow controls remain available.");
    } finally {
      setAnalyzing(false);
    }
  }

  function openTracking() {
    if (!linkedIncident) return;
    if (isTerminalIncidentStatus(linkedIncident.status)) {
      setSelectedIncidentId(linkedIncident.id);
      navigate(SOC_ROUTES.incidents);
      return;
    }
    setTrackingIncidentId(linkedIncident.id);
    navigate(SOC_ROUTES.incidentTracking);
  }

  return (
    <>
      <PageHeader
        title="Quick Resolve"
        description="Triage one alert, manage its incident, record notes, and review AI guidance without changing workspaces."
        actions={<SearchableAlertPicker alerts={selectableAlerts} value={selectedAlertId} onChange={setSelectedAlertId} />}
      />

      {resourceError ? (
        <ErrorState message={resourceError} onRetry={() => Promise.all([refresh("alerts"), refresh("events"), refresh("incidents"), refresh("notes")])} />
      ) : loading ? (
        <Panel title="Preparing Quick Resolve"><div className="detail-placeholder"><span className="soc-spinner" /><strong>Synchronizing investigation data</strong><span>Alerts, incidents, notes, and matched evidence are loading.</span></div></Panel>
      ) : !selectedAlert ? (
        <Panel title="Select one alert" subtitle={`${selectableAlerts.length} active alerts are available`}>
          <div className="quick-resolve-empty"><Search size={25} /><strong>Choose an alert to begin</strong><p>The workspace will keep the selection empty until you explicitly choose a record.</p></div>
        </Panel>
      ) : (
        <>
          <section className="quick-resolve-summary" aria-label="Selected alert summary">
            <div><span>Alert</span><strong className="mono">{selectedAlert.id}</strong></div>
            <div><span>Severity</span><SeverityBadge severity={selectedAlert.severity} /></div>
            <div><span>Alert status</span><StatusBadge status={selectedAlert.status} /></div>
            <div><span>Incident</span>{linkedIncident ? <strong className="mono">{linkedIncident.id}</strong> : <em>Not created</em>}</div>
            <div><span>Risk</span><strong>{selectedAlert.risk}/100</strong></div>
          </section>

          {workflowError && <InlineNotice tone="error" title="Workflow could not continue">{workflowError}</InlineNotice>}

          <div className="quick-resolve-grid">
            <Panel className="quick-evidence-panel span-2" title="Alert evidence" subtitle={`${evidence.length} matched records · ${selectedAlert.ruleId}`} actions={<button className="soc-text-button" type="button" onClick={() => navigate(SOC_ROUTES.alerts)}>Open full alert <FileSearch size={13} /></button>}>
              <div className="quick-alert-overview"><div><h3>{selectedAlert.title}</h3><p>{selectedAlert.summary}</p><dl><div><dt>Source IP</dt><dd className="mono">{selectedAlert.sourceIp}</dd></div><div><dt>Affected user</dt><dd className="mono">{selectedAlert.user || "Unknown"}</dd></div><div><dt>Observed</dt><dd>{formatTimestamp(selectedAlert.observedAt || selectedAlert.createdAt)}</dd></div></dl></div><RiskMeter value={selectedAlert.risk} /></div>
              <div className="quick-evidence-list">{evidence.slice(0, 5).map((event) => <article key={event.id}><div><code>{event.id}</code><StatusBadge status={event.status} /></div><strong>{event.event}</strong><p className="mono">{formatTimestamp(event.timestamp)} · {event.sourceIp} · {event.user}</p><span>{event.message}</span></article>)}{!evidence.length && <p className="empty-inline">No normalized evidence is linked to this alert.</p>}</div>
              {rule && <div className="quick-rule"><span><Sparkles size={15} />Detection rule</span><strong>{rule.id} · {rule.name}</strong><p>{rule.description}</p><code>{rule.query}</code></div>}
            </Panel>

            <Panel title="Response workflow" subtitle="Persisted alert and incident controls">
              <div className="quick-workflow-card">
                <div className="quick-workflow-state"><span><Workflow size={17} /></span><div><strong>{linkedIncident ? linkedIncident.title : "Incident required"}</strong><p>{linkedIncident ? `${linkedIncident.id} · ${linkedIncident.owner}` : "Create an incident from this alert to continue."}</p></div></div>
                {linkedIncident && <div className="quick-status-pair"><div><small>Alert</small><StatusBadge status={selectedAlert.status} /></div><div><small>Incident</small><StatusBadge status={linkedIncident.status} /></div></div>}
                {isTerminalIncidentStatus(linkedIncident?.status) && <p className="quick-completion"><Check size={14} />{linkedIncident.status === "false positive" ? "Marked false positive" : "Resolved"} by <strong>{linkedIncident.completedBy || "Unknown analyst"}</strong> · {formatTimestamp(linkedIncident.completedAt || linkedIncident.updated)}</p>}
                {!linkedIncident ? <button className="soc-button primary full" type="button" disabled={!canWrite || mutation.loading} onClick={createFromAlert}><ShieldPlus size={15} />Create incident</button> : <>
                  <button className="soc-button secondary full" type="button" disabled={!canWrite || mutation.loading || linkedIncident.status === "investigating" || isTerminalIncidentStatus(linkedIncident.status)} onClick={startInvestigation}><PlayCircle size={15} />Start investigation</button>
                  <button className="soc-button primary full" type="button" disabled={!canWrite || mutation.loading || isTerminalIncidentStatus(linkedIncident.status)} onClick={resolveInvestigation}><CircleCheckBig size={15} />Resolve alert and incident</button>
                  <button className="soc-button secondary full" type="button" disabled={!canWrite || mutation.loading || isTerminalIncidentStatus(linkedIncident.status)} onClick={markFalsePositive}><CircleX size={15} />Mark false positive</button>
                  <button className="soc-text-button" type="button" onClick={openTracking}>{isTerminalIncidentStatus(linkedIncident.status) ? "View incident history" : "Open full tracking timeline"}</button>
                </>}
              </div>
            </Panel>

            <Panel title="Resolution checklist" subtitle={`${checkedSteps.length} of ${CHECKLIST.length} reviewed · session checklist`}>
              <div className="quick-checklist">{CHECKLIST.map((item, index) => <label key={item} className={checkedSteps.includes(index) ? "complete" : ""}><input type="checkbox" checked={checkedSteps.includes(index)} disabled={!canWrite} onChange={(event) => toggleChecklist(index, event.target.checked)} /><span>{checkedSteps.includes(index) ? <Check size={14} /> : index + 1}</span><strong>{item}</strong></label>)}</div>
            </Panel>

            <Panel title="Analyst note" subtitle={linkedIncident ? `${incidentNotes.length} of ${MAX_INCIDENT_NOTES} incident notes used` : "Create an incident before recording a note"}>
              <form className="quick-note-form" onSubmit={saveNote} noValidate><textarea value={note} disabled={!canWrite || !linkedIncident || incidentNotes.length >= MAX_INCIDENT_NOTES} maxLength="1200" rows="5" onChange={(event) => { setNote(event.target.value); if (noteError) setNoteError(""); }} placeholder={linkedIncident ? "Record verification, decision, and next action…" : "Create an incident to enable notes"} aria-label="Quick resolve analyst note" aria-invalid={Boolean(noteError)} aria-describedby={noteError ? "quick-note-error" : undefined} /><ValidationMessage id="quick-note-error">{noteError}</ValidationMessage><button className="soc-button primary" type="submit" disabled={!canWrite || mutation.loading || !linkedIncident || !note.trim()}><MessageSquareText size={15} />Add note</button></form>
              {incidentNotes.slice(0, 2).map((item) => <article className="quick-note-preview" key={item.id}><strong>{item.author}</strong><small>{formatTimestamp(item.updatedAt)}</small><p>{item.body}</p></article>)}
            </Panel>

            <Panel className="quick-ai-panel" title="AI analysis" subtitle="Evidence-grounded guidance with human approval" actions={<button className="soc-button secondary compact" type="button" disabled={!aiEnabled || analyzing} onClick={runAnalysis}>{analyzing ? <span className="soc-spinner small" /> : <Bot size={15} />}{analyzing ? "Analyzing…" : "Analyze alert"}</button>}>
              {!aiEnabled && <InlineNotice tone="warning" title="AI assistant disabled">Enable it in Settings to add AI guidance to this workflow.</InlineNotice>}
              {analysisError && <InlineNotice tone="error" title="Analysis unavailable">{analysisError}</InlineNotice>}
              {analysis ? <div className="quick-ai-result"><div><StatusBadge status="review required" /><strong>{analysis.verdict}</strong></div><p>{analysis.summary}</p><h4>Recommended actions</h4><ul>{analysis.actions.slice(0, 4).map((item) => <li key={item}><CircleCheckBig size={14} />{item}</li>)}</ul><button className="soc-text-button" type="button" onClick={() => navigate(SOC_ROUTES.aiAnalysis)}>Continue in AI Analysis</button></div> : !analyzing && <div className="quick-ai-empty"><Bot size={23} /><strong>AI review is optional</strong><p>Run an analysis after checking the matched evidence and rule logic.</p></div>}
            </Panel>
          </div>
        </>
      )}
    </>
  );
}
