import { useEffect, useState } from "react";
import { Check, Clock3, ListFilter, MessageSquareText, PlayCircle, ShieldCheck, Workflow } from "lucide-react";
import { SOC_ROUTES } from "../../hooks/useAuthRoute";
import IncidentStatusConfirmDialog from "../components/IncidentStatusConfirmDialog";
import { useSocWorkspace } from "../context/SocWorkspaceContext";
import { formatTimestamp } from "../utils/eventUtils";
import { INCIDENT_STATUSES, incidentStatusLabel, isTerminalIncidentStatus, nextIncidentWorkflowAction } from "../utils/incidentWorkflow";
import { ErrorState, InlineNotice, LoadingState, PageHeader, Panel, SeverityBadge, StatusBadge, ValidationMessage } from "../components/Ui";

const MAX_INCIDENT_NOTES = 5;
const PLAYBOOK_STEPS = [
  "Validate source IP reputation and enrich with threat intelligence",
  "Review matched authentication and detection events to confirm scope",
  "Contain affected assets and revoke active sessions if compromise is confirmed",
  "Eradicate the root cause: reset credentials, patch, or remove persistence",
  "Restore affected systems and monitor for recurrence",
  "Document the response decision, root cause, and lessons learned",
];
const WORKFLOW_STATES = ["Open", "Investigating", "Outcome recorded"];

function workflowIndex(status) {
  if (["investigating", "awaiting approval", "escalated", "contained"].includes(status)) return 1;
  if (status === "resolved") return 2;
  if (isTerminalIncidentStatus(status)) return 2;
  return 0;
}

function defaultTasks(incident) {
  const completed = isTerminalIncidentStatus(incident.status)
    ? PLAYBOOK_STEPS.length
    : incident.status === "investigating" ? Math.ceil(PLAYBOOK_STEPS.length / 2) : 0;
  return PLAYBOOK_STEPS.map((title, index) => ({ id: index + 1, title, owner: incident.owner || "Unassigned", done: index < completed }));
}

export default function IncidentTrackingPage({ navigate }) {
  const {
    canWrite,
    notes,
    mutation,
    resources,
    refresh,
    addNote,
    updateIncidentStatus,
    timeFilteredIncidents: allIncidents,
    trackingIncidentId,
    setTrackingIncidentId,
    setSelectedIncidentId,
  } = useSocWorkspace();
  const [tasksByIncident, setTasksByIncident] = useState({});
  const [note, setNote] = useState("");
  const [noteError, setNoteError] = useState("");
  const [pendingTerminalStatus, setPendingTerminalStatus] = useState(null);
  const incidents = allIncidents.filter((item) => !isTerminalIncidentStatus(item.status));
  const incident = incidents.find((item) => item.id === trackingIncidentId) || incidents[0] || null;
  const tasks = incident ? tasksByIncident[incident.id] || defaultTasks(incident) : [];
  const allIncidentNotes = notes.filter((item) => item.linkedType === "incident" && item.linkedId === incident?.id);
  const visibleIncidentNotes = allIncidentNotes.filter((item) => !item.archived);
  const noteLimitReached = allIncidentNotes.length >= MAX_INCIDENT_NOTES;
  const statusAction = incident ? nextIncidentWorkflowAction(incident.status) : null;
  const currentWorkflowIndex = incident ? workflowIndex(incident.status) : 0;

  useEffect(() => {
    if (incident && incident.id !== trackingIncidentId) setTrackingIncidentId(incident.id);
  }, [incident, setTrackingIncidentId, trackingIncidentId]);

  useEffect(() => {
    setNote("");
    setNoteError("");
  }, [incident?.id]);

  if (resources.incidents.loading || resources.notes.loading) return <LoadingState label="Loading incident tracking workspace…" />;
  if (resources.incidents.error || resources.notes.error) return <ErrorState message={resources.incidents.error || resources.notes.error} onRetry={() => Promise.all([refresh("incidents"), refresh("notes")])} />;
  if (!incident) return (
    <>
      <PageHeader title="Incident Tracking" description="Coordinate response work after an alert has been promoted to an incident." actions={<button className="soc-button secondary" type="button" onClick={() => navigate(SOC_ROUTES.incidents)}>Go to incident queue</button>} />
      <Panel title="No incident in this time range">
        <div className="detail-placeholder"><ShieldCheck size={24} /><strong>No incident is available for tracking</strong><span>Change the global time range or create an incident from an alert.</span></div>
      </Panel>
    </>
  );

  function updateTask(taskId, done) {
    setTasksByIncident((current) => ({
      ...current,
      [incident.id]: (current[incident.id] || defaultTasks(incident)).map((item) => item.id === taskId ? { ...item, done } : item),
    }));
  }

  function requestIncidentStatus(nextStatus) {
    if (isTerminalIncidentStatus(nextStatus)) {
      setPendingTerminalStatus({ incident: { ...incident }, status: nextStatus });
      return;
    }
    void updateIncidentStatus(incident.id, nextStatus);
  }

  async function confirmTerminalStatus() {
    if (!pendingTerminalStatus) return;
    const { incident: target, status: nextStatus } = pendingTerminalStatus;

    // A tracking selection may also be the Incidents page selection. Clearing
    // it prevents a terminal workflow update from masquerading as a history link.
    setSelectedIncidentId(null);
    const saved = await updateIncidentStatus(target.id, nextStatus);
    if (!saved) setTrackingIncidentId(target.id);
    setPendingTerminalStatus(null);
  }

  async function applyWorkflowStatusAction() {
    if (!incident || !statusAction) return;
    const [nextStatus] = statusAction;

    // Dedicated workflow buttons are deliberate actions. Only terminal values
    // chosen from a dropdown require the additional confirmation dialog.
    if (isTerminalIncidentStatus(nextStatus)) setSelectedIncidentId(null);
    const saved = await updateIncidentStatus(incident.id, nextStatus);
    if (!saved && isTerminalIncidentStatus(nextStatus)) setTrackingIncidentId(incident.id);
  }

  async function submitNote(event) {
    event.preventDefault();
    if (noteLimitReached) {
      setNoteError("This incident already has the maximum of 5 analyst notes.");
      return;
    }
    const normalizedNote = note.trim();
    if (normalizedNote.length < 12) {
      setNoteError("Investigation note must be at least 12 characters.");
      return;
    }
    const saved = await addNote({
      title: `${incident.id} investigation update`,
      body: normalizedNote,
      tags: ["incident-tracking"],
      linkedType: "incident",
      linkedId: incident.id,
    });
    if (saved) setNote("");
  }

  return (
    <>
      <PageHeader
        title="Incident Tracking"
        description={`Coordinate the response playbook, status, and analyst record for ${incident.id}.`}
        actions={<><label className="tracking-incident-picker"><span><ListFilter size={14} />Active incident</span><select value={incident.id} onChange={(event) => setTrackingIncidentId(event.target.value)}>{incidents.map((item) => <option key={item.id} value={item.id}>{item.id} · {item.title}</option>)}</select></label><button className="soc-button secondary" type="button" onClick={() => navigate(SOC_ROUTES.incidents)}>Back to queue</button></>}
      />
      <div className="tracking-summary">
        <div><span>Incident</span><strong className="mono">{incident.id}</strong></div>
        <div><span>Priority</span><SeverityBadge severity={incident.priority} /></div>
        <div><span>Status</span><StatusBadge status={incident.status} /></div>
        <div><span>Assignee</span><strong>{incident.owner}</strong></div>
        <div><span>Response SLA</span><strong className={incident.priority === "critical" ? "critical-text" : ""}>{incident.sla}</strong></div>
      </div>
      <div className="tracking-grid">
        <Panel className="span-2" title="Response playbook" subtitle={`${tasks.filter((task) => task.done).length} of ${tasks.length} steps complete · stored for this session`}>
          <div className="playbook-list">
            {tasks.map((task, index) => (
              <label key={task.id} className={task.done ? "complete" : ""}>
                <input type="checkbox" checked={task.done} disabled={!canWrite} onChange={(event) => updateTask(task.id, event.target.checked)} />
                <span className="playbook-step">{task.done ? <Check size={15} /> : index + 1}</span>
                <span><strong>{task.title}</strong><small>Assignee · {task.owner}</small></span>
                <StatusBadge status={task.done ? "done" : "pending"} />
              </label>
            ))}
          </div>
        </Panel>
        <Panel title="Incident control">
          <div className="incident-control-card">
            <header><span><Workflow size={18} /></span><div><h3>Response workflow</h3><p>Move this incident through the persisted investigation lifecycle.</p></div></header>
            <ol key={`${incident.id}-${incident.status}`} className="incident-state-track" aria-label="Incident workflow progress">{WORKFLOW_STATES.map((label, index) => <li key={label} style={{ "--step-index": index }} className={index < currentWorkflowIndex ? "complete" : index === currentWorkflowIndex ? "current" : ""}><i>{index < currentWorkflowIndex ? <Check size={11} /> : index + 1}</i><span>{label}</span></li>)}</ol>
            <div className="incident-current-state"><span>Current state</span><StatusBadge status={incident.status} /></div>
            <label className="status-control"><span>Incident status</span><select value={incident.status} disabled={!canWrite || mutation.loading} onChange={(event) => requestIncidentStatus(event.target.value)}>{INCIDENT_STATUSES.map((item) => <option key={item} value={item}>{incidentStatusLabel(item)}</option>)}</select></label>
            {statusAction ? <button className="soc-button primary full" type="button" disabled={!canWrite || mutation.loading} title={!canWrite ? "Viewer access is read-only." : undefined} onClick={applyWorkflowStatusAction}>{statusAction[1]}</button> : <p className="empty-inline">No further status action is required.</p>}
          </div>
        </Panel>
        <Panel title="Investigation timeline">
          <ol className="timeline-list">
            <li><PlayCircle size={16} /><div><strong>Incident record available</strong><span>{formatTimestamp(incident.updated)} · {incident.sourceAlertId ? `Alert ${incident.sourceAlertId}` : "SOC queue"}</span></div></li>
            <li><Clock3 size={16} /><div><strong>Status: {incident.status}</strong><span>{incident.owner || "Unassigned"} · current assignee</span></div></li>
            {visibleIncidentNotes.slice(0, 3).map((item) => <li key={item.id}><MessageSquareText size={16} /><div><strong>{item.title}</strong><span>{formatTimestamp(item.updatedAt)} · {item.author}</span></div></li>)}
          </ol>
        </Panel>
        <Panel className="span-2" title="Analyst notes" subtitle={allIncidentNotes.length > MAX_INCIDENT_NOTES ? `${allIncidentNotes.length} existing · ${MAX_INCIDENT_NOTES}-note limit enforced` : `${allIncidentNotes.length} of ${MAX_INCIDENT_NOTES} notes used`}>
          {noteLimitReached && <InlineNotice tone="warning" title="Note limit reached">Delete an existing incident note from Analyst Notes before adding another.</InlineNotice>}
          <form className="note-form" onSubmit={submitNote} noValidate><textarea className={noteError ? "has-error" : undefined} value={note} disabled={!canWrite || noteLimitReached} onChange={(event) => { setNote(event.target.value); if (noteError) setNoteError(""); }} maxLength="500" rows="3" placeholder={noteLimitReached ? "Maximum of 5 notes reached" : "Add an evidence-backed investigation note…"} aria-label="Investigation note" aria-invalid={Boolean(noteError)} aria-describedby={noteError ? "tracking-note-error" : undefined} /><ValidationMessage id="tracking-note-error">{noteError}</ValidationMessage><button className="soc-button primary" type="submit" disabled={!canWrite || mutation.loading || noteLimitReached || !note.trim()}>Add note</button></form>
          <ul className="notes-list" role="region" aria-label="Scrollable incident analyst notes" tabIndex="0">{visibleIncidentNotes.map((item) => <li key={item.id}><span className="soc-avatar">{item.author.split(" ").map((part) => part[0]).join("").slice(0, 2)}</span><div><strong>{item.author}</strong><small>{formatTimestamp(item.updatedAt)}</small><p>{item.body}</p></div></li>)}</ul>
          {!visibleIncidentNotes.length && <p className="empty-inline">No active analyst notes are linked to this incident yet.</p>}
        </Panel>
      </div>
      <IncidentStatusConfirmDialog
        disabled={mutation.loading}
        incident={pendingTerminalStatus?.incident}
        status={pendingTerminalStatus?.status}
        onCancel={() => setPendingTerminalStatus(null)}
        onConfirm={confirmTerminalStatus}
      />
    </>
  );
}
