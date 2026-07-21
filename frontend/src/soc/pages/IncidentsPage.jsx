import { useEffect, useMemo, useState } from "react";
import { BookOpenCheck, CheckCircle2, Download, History, Plus, RefreshCw, Search, X } from "lucide-react";
import { SOC_ROUTES } from "../../hooks/useAuthRoute";
import IncidentStatusConfirmDialog from "../components/IncidentStatusConfirmDialog";
import { useSocWorkspace } from "../context/SocWorkspaceContext";
import { socRepository } from "../services/socRepository";
import { downloadIncidentsCsv, formatTimestamp } from "../utils/eventUtils";
import { validateIncidentDraft } from "../utils/formValidation";
import { nextIncidentId } from "../utils/recordIds";
import { paginateRecords } from "../utils/pagination";
import { INCIDENT_STATUSES, incidentStatusLabel, isTerminalIncidentStatus } from "../utils/incidentWorkflow";
import {
  ErrorState,
  LoadingState,
  PageHeader,
  Panel,
  SeverityBadge,
  StatCard,
  StatusBadge,
  TablePagination,
  ValidationMessage,
} from "../components/Ui";

const PAGE_SIZE = 10;

function formatIncidentUpdated(value) {
  if (!value || value === "Just now") return value || "Unknown time";
  const formatted = formatTimestamp(value);
  return formatted === "Unknown time" ? value : formatted;
}

export default function IncidentsPage({ navigate }) {
  const {
    alerts,
    canWrite,
    currentActor,
    incidents,
    timeFilteredIncidents,
    events,
    detectionRules,
    mutation,
    repositoryMode,
    resources,
    refresh,
    setTrackingIncidentId,
    selectedIncidentId,
    setSelectedIncidentId,
    updateIncidentStatus,
    updateIncidentAssignee,
    createIncident: createWorkspaceIncident,
  } = useSocWorkspace();
  const [query, setQuery] = useState("");
  const [priority, setPriority] = useState("");
  const [status, setStatus] = useState("");
  const [page, setPage] = useState(1);
  const [createOpen, setCreateOpen] = useState(false);
  const [createErrors, setCreateErrors] = useState({});
  const [historyOpen, setHistoryOpen] = useState(false);
  const [historyQuery, setHistoryQuery] = useState("");
  const [pendingTerminalStatus, setPendingTerminalStatus] = useState(null);
  const [assignableUsers, setAssignableUsers] = useState([]);

  // A lightweight, role-appropriate directory for assignee pickers — kept
  // local to this page rather than in the shared workspace context, since
  // it's only needed here and in the incident detail's reassignment control.
  useEffect(() => {
    let active = true;
    socRepository.getAssignableUsers()
      .then((users) => { if (active) setAssignableUsers(users); })
      .catch(() => { if (active) setAssignableUsers([]); });
    return () => { active = false; };
  }, []);

  const usersById = useMemo(() => new Map(assignableUsers.map((user) => [user.id, user])), [assignableUsers]);

  function assigneeName(user) {
    return user.fullName || user.username;
  }

  function displayOwner(incident) {
    if (!incident.assignedUserId) return incident.owner || "Unassigned";
    const user = usersById.get(incident.assignedUserId);
    return user ? assigneeName(user) : incident.owner;
  }

  // Resolved and false-positive outcomes leave the active queue but remain
  // available through the searchable investigation history.
  const records = timeFilteredIncidents.filter((incident) => !isTerminalIncidentStatus(incident.status));
  const availableAlerts = alerts.filter((alert) => (
    alert.sourceAlertId && !incidents.some((incident) => incident.sourceAlertId === alert.sourceAlertId)
  ));
  const filtered = useMemo(() => records.filter((incident) => {
    const text = `${incident.id} ${incident.title} ${incident.owner} ${displayOwner(incident)} ${incident.summary}`.toLowerCase();
    return (!query || text.includes(query.toLowerCase())) && (!priority || incident.priority === priority) && (!status || incident.status === status);
  }), [records, priority, query, status, usersById]);
  const historyRecords = useMemo(() => incidents
    .filter((incident) => isTerminalIncidentStatus(incident.status))
    .filter((incident) => {
      const searchText = `${incident.id} ${incident.title} ${incident.owner} ${displayOwner(incident)} ${incident.priority} ${incident.summary}`.toLowerCase();
      return !historyQuery || searchText.includes(historyQuery.toLowerCase());
    })
    .sort((a, b) => new Date(b.completedAt || b.updated) - new Date(a.completedAt || a.updated)), [historyQuery, incidents, usersById]);
  const pagination = useMemo(() => paginateRecords(filtered, page, PAGE_SIZE), [filtered, page]);
  const pageIncidents = pagination.items;
  const selected = records.find((incident) => incident.id === selectedIncidentId) || null;
  const selectedEvents = selected ? events.filter((event) => selected.eventIds.includes(event.id)) : [];
  const selectedRules = [...new Set(selectedEvents.map((event) => event.rule.split(" · ")[0]))]
    .map((ruleId) => detectionRules[ruleId])
    .filter(Boolean);
  const loading = resources.incidents.loading || resources.events.loading || resources.alerts.loading;
  const error = resources.incidents.error || resources.events.error || resources.alerts.error;

  useEffect(() => {
    setPage(1);
  }, [priority, query, status]);

  useEffect(() => {
    if (!selectedIncidentId) return;
    const target = incidents.find((incident) => incident.id === selectedIncidentId);
    if (!target) return;
    if (isTerminalIncidentStatus(target.status)) {
      setHistoryQuery(target.id);
      setHistoryOpen(true);
      return;
    }
    const targetIndex = filtered.findIndex((incident) => incident.id === selectedIncidentId);
    if (targetIndex >= 0) setPage(Math.floor(targetIndex / PAGE_SIZE) + 1);
  }, [filtered, incidents, selectedIncidentId]);

  if (loading) return <LoadingState label="Loading incident queue…" />;
  if (error) return <ErrorState message={error} onRetry={() => Promise.all([refresh("incidents"), refresh("events"), refresh("alerts")])} />;

  function startSelectedInvestigation() {
    if (!selected) return;
    requestIncidentStatus(selected, "investigating");
  }

  function requestIncidentStatus(incident, nextStatus) {
    if (isTerminalIncidentStatus(nextStatus)) {
      setPendingTerminalStatus({ incident: { ...incident }, status: nextStatus });
      return;
    }
    void updateIncidentStatus(incident.id, nextStatus);
  }

  async function confirmTerminalStatus() {
    if (!pendingTerminalStatus) return;
    const { incident, status: nextStatus } = pendingTerminalStatus;

    // Clear the active selection before the optimistic update removes the row.
    // Explicit links to an already-completed incident still open history.
    setSelectedIncidentId(null);
    const saved = await updateIncidentStatus(incident.id, nextStatus);
    if (!saved) setSelectedIncidentId(incident.id);
    setPendingTerminalStatus(null);
  }

  function openTracking() {
    if (selected) setTrackingIncidentId(selected.id);
    navigate(SOC_ROUTES.incidentTracking);
  }

  // A terminal incident ID is shared only to open the requested history item.
  // Clear that consumed selection when the analyst dismisses the modal so a
  // later visit to this route does not reopen history unexpectedly.
  function closeHistory() {
    const linkedSelection = incidents.find((incident) => incident.id === selectedIncidentId);
    setHistoryOpen(false);
    setHistoryQuery("");
    if (linkedSelection && isTerminalIncidentStatus(linkedSelection.status)) {
      setSelectedIncidentId(null);
    }
  }

  async function createIncident(event) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const title = String(form.get("title") || "").trim();
    const summary = String(form.get("summary") || "").trim();
    const sourceAlertId = Number(form.get("sourceAlertId")) || null;
    const assignedUserId = Number(form.get("assignedUserId")) || null;
    const assignedUser = assignedUserId ? usersById.get(assignedUserId) : null;
    const nextErrors = {
      ...validateIncidentDraft({ title, summary }),
      sourceAlertId: repositoryMode === "api" && !sourceAlertId
        ? "Select the alert that opened this investigation."
        : undefined,
    };
    setCreateErrors(nextErrors);

    const firstInvalidField = nextErrors.sourceAlertId
      ? "sourceAlertId"
      : nextErrors.title
        ? "title"
        : nextErrors.summary
          ? "summary"
          : "";
    if (firstInvalidField) {
      event.currentTarget.elements.namedItem(firstInvalidField)?.focus();
      return;
    }

    const incident = {
      id: nextIncidentId(incidents),
      title,
      owner: assignedUser ? assigneeName(assignedUser) : currentActor,
      assignedUserId,
      priority: String(form.get("priority") || "medium"),
      status: "open",
      updated: "Just now",
      sla: "Within target",
      summary,
      sourceAlertId,
      eventIds: alerts.find((alert) => alert.sourceAlertId === sourceAlertId)?.evidenceIds || [],
    };
    const created = await createWorkspaceIncident(incident);
    if (created) {
      setSelectedIncidentId(created.id);
      setCreateOpen(false);
    }
  }

  return (
    <>
      <PageHeader
        title="Incidents"
        description="Track investigations, document actions, and manage escalation decisions."
        actions={<><button className="soc-button secondary" type="button" onClick={() => { setHistoryQuery(""); setHistoryOpen(true); }}><History size={15} />Incident history</button><button className="soc-button secondary" type="button" disabled={mutation.loading} onClick={() => Promise.all([refresh("incidents"), refresh("events"), refresh("alerts")])}><RefreshCw size={15} />Refresh</button><button className="soc-button primary" type="button" disabled={!canWrite || mutation.loading || (repositoryMode === "api" && !availableAlerts.length)} title={!canWrite ? "Viewer access is read-only." : repositoryMode === "api" && !availableAlerts.length ? "All persisted alerts are already linked to incidents." : undefined} onClick={() => { setCreateErrors({}); setCreateOpen(true); }}><Plus size={15} />Create incident</button></>}
      />

      <div className="soc-stats-grid">
        <StatCard label="Open incidents" value={records.filter((item) => item.status === "open").length} trend={`${records.filter((item) => item.priority === "critical").length} critical`} />
        <StatCard label="Investigating" value={records.filter((item) => item.status === "investigating").length} trend="Active analyst work" />
        <StatCard label="Needs review" value={records.filter((item) => item.status === "open").length} trend="Current queue" tone="critical" />
        <StatCard label="Incident history" value={incidents.filter((item) => isTerminalIncidentStatus(item.status)).length} trend="Completed investigations" tone="success" />
      </div>

      <section className="filter-bar" aria-label="Incident filters">
        <label className="filter-search"><Search size={16} /><span className="sr-only">Search incidents</span><input type="search" maxLength="200" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search incidents…" /></label>
        <label><span className="sr-only">Priority</span><select value={priority} onChange={(event) => setPriority(event.target.value)}><option value="">All priorities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></label>
        <label><span className="sr-only">Status</span><select value={status} onChange={(event) => setStatus(event.target.value)}><option value="">All active statuses</option><option value="open">Open</option><option value="investigating">Investigating</option></select></label>
        <button className="soc-button secondary" type="button" disabled={!selected} title={!selected ? "Select an incident first." : undefined} onClick={openTracking}>Open tracking workspace</button>
      </section>

      <div className="incident-workspace">
        <Panel title="Incident queue" subtitle={`${filtered.length} matching records${filtered.length > PAGE_SIZE ? ` · page ${pagination.page} of ${pagination.pageCount}` : ""}`}>
          <div className={`soc-table-scroll${filtered.length > PAGE_SIZE ? " with-pagination" : ""}`} role="region" aria-label="Scrollable incident queue" tabIndex="0">
            <table className="soc-table incidents-table">
              <thead><tr><th>Incident</th><th>Title</th><th>Assignee</th><th>Priority</th><th>Status</th><th>Updated</th></tr></thead>
              <tbody>
                {pageIncidents.map((incident) => (
                  <tr key={incident.id} className={selected?.id === incident.id ? "selected" : ""} onClick={() => setSelectedIncidentId(incident.id)} tabIndex="0" onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); setSelectedIncidentId(incident.id); } }}>
                    <td className="mono">{incident.id}</td>
                    <td><strong>{incident.title}</strong><small>{incident.sla}</small></td>
                    <td>{displayOwner(incident)}</td>
                    <td><SeverityBadge severity={incident.priority} /></td>
                    <td><StatusBadge status={incident.status} /></td>
                    <td>{formatIncidentUpdated(incident.updated)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {!filtered.length && <div className="table-empty"><Search size={22} /><strong>No incidents match these filters</strong><span>Adjust the search or choose a different status.</span></div>}
          </div>
          <TablePagination label="incidents" page={pagination.page} pageSize={PAGE_SIZE} totalItems={filtered.length} onPageChange={setPage} />
        </Panel>

        <Panel className="incident-detail-panel" title={selected ? selected.id : "Investigation details"} aria-label="Scrollable incident details" tabIndex="0">
          {selected ? (
            <div className="incident-detail">
              <div className="incident-detail-badges"><SeverityBadge severity={selected.priority} /><StatusBadge status={selected.status} /></div>
              <h3>{selected.title}</h3>
              <p>{selected.summary}</p>
              <dl>
                <div><dt>Response SLA</dt><dd>{selected.sla}</dd></div>
                <div><dt>Related events</dt><dd>{selected.eventIds.length || "None linked"}</dd></div>
                <div><dt>Last updated</dt><dd>{formatIncidentUpdated(selected.updated)}</dd></div>
              </dl>
              <label className="status-control">
                <span>Assignee</span>
                <select
                  value={selected.assignedUserId || ""}
                  disabled={mutation.loading || !canWrite}
                  title={!canWrite ? "Viewer access is read-only." : undefined}
                  onChange={(event) => {
                    const nextId = Number(event.target.value) || null;
                    const nextUser = nextId ? usersById.get(nextId) : null;
                    void updateIncidentAssignee(selected.id, nextId, nextUser ? assigneeName(nextUser) : null);
                  }}
                >
                  <option value="">Unassigned</option>
                  {assignableUsers.map((user) => (
                    <option key={user.id} value={user.id}>{assigneeName(user)}{user.role ? ` · ${user.role}` : ""}</option>
                  ))}
                </select>
              </label>
              <label className="status-control"><span>Incident status</span><select value={selected.status} disabled={mutation.loading || !canWrite} title={!canWrite ? "Viewer access is read-only." : undefined} onChange={(event) => requestIncidentStatus(selected, event.target.value)}>{INCIDENT_STATUSES.map((item) => <option key={item} value={item}>{incidentStatusLabel(item)}</option>)}</select></label>
              <div className="incident-evidence-section">
                <h4>Matched log evidence <span>{selectedEvents.length}</span></h4>
                {selectedEvents.map((event) => <article key={event.id}><div><code>{event.id}</code><StatusBadge status={event.status} /></div><strong>{event.event}</strong><p className="mono">{formatTimestamp(event.timestamp)} · {event.sourceIp} · user={event.user}</p></article>)}
                {!selectedEvents.length && <p className="empty-inline">No normalized events are linked yet.</p>}
              </div>
              <div className="incident-rules-section">
                <h4>Detection rules <span>{selectedRules.length}</span></h4>
                {selectedRules.map((rule) => <article key={rule.id}><div><code>{rule.id}</code><StatusBadge status={rule.status} /></div><strong>{rule.name}</strong><p>{rule.technique}</p></article>)}
                {!selectedRules.length && <p className="empty-inline">No detection rule is linked yet.</p>}
              </div>
              {selected.status === "open" && <button className="soc-button primary full" type="button" disabled={mutation.loading || !canWrite} onClick={startSelectedInvestigation}><CheckCircle2 size={15} />Start investigation</button>}
              <button className="soc-button secondary full" type="button" onClick={openTracking}>Open investigation timeline</button>
              <button className="soc-button secondary full" type="button" onClick={() => navigate(SOC_ROUTES.analystNotes)}><BookOpenCheck size={15} />Open analyst notes</button>
            </div>
          ) : (
            <div className="detail-placeholder"><Search size={24} /><strong>Select an incident</strong><span>Review assignee, SLA, linked evidence, and response actions.</span></div>
          )}
        </Panel>
      </div>

      {createOpen && (
        <div className="soc-modal-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) setCreateOpen(false); }}>
          <section className="soc-modal" role="dialog" aria-modal="true" aria-labelledby="create-incident-title">
            <header><div><h2 id="create-incident-title">Create incident</h2><p>Record the minimum information needed to begin investigation.</p></div><button type="button" disabled={mutation.loading} onClick={() => setCreateOpen(false)} aria-label="Close"><X size={18} /></button></header>
            <form onSubmit={createIncident} noValidate>
              {repositoryMode === "api" && (
                <label className={createErrors.sourceAlertId ? "has-error" : undefined}>
                  Source alert
                  <select
                    name="sourceAlertId"
                    defaultValue=""
                    aria-invalid={Boolean(createErrors.sourceAlertId)}
                    aria-describedby={createErrors.sourceAlertId ? "incident-source-error" : undefined}
                    onChange={() => {
                      if (createErrors.sourceAlertId) {
                        setCreateErrors((current) => ({ ...current, sourceAlertId: undefined }));
                      }
                    }}
                  >
                    <option value="">Select an unlinked alert</option>
                    {availableAlerts.map((alert) => (
                      <option key={alert.id} value={alert.sourceAlertId}>
                        {alert.id} - {alert.title}
                      </option>
                    ))}
                  </select>
                  <ValidationMessage id="incident-source-error">{createErrors.sourceAlertId}</ValidationMessage>
                </label>
              )}
              <label className={createErrors.title ? "has-error" : undefined}>Title<input name="title" maxLength="90" autoFocus aria-invalid={Boolean(createErrors.title)} aria-describedby={createErrors.title ? "incident-title-error" : undefined} onChange={() => { if (createErrors.title) setCreateErrors((current) => ({ ...current, title: undefined })); }} /><ValidationMessage id="incident-title-error">{createErrors.title}</ValidationMessage></label>
              <label>Priority<select name="priority" defaultValue="medium"><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></label>
              <label>
                Assignee
                <select name="assignedUserId" defaultValue="">
                  <option value="">Unassigned</option>
                  {assignableUsers.map((user) => (
                    <option key={user.id} value={user.id}>{assigneeName(user)}{user.role ? ` · ${user.role}` : ""}</option>
                  ))}
                </select>
              </label>
              <label className={createErrors.summary ? "has-error" : undefined}>Summary<textarea name="summary" maxLength="500" rows="4" aria-invalid={Boolean(createErrors.summary)} aria-describedby={createErrors.summary ? "incident-summary-error" : undefined} onChange={() => { if (createErrors.summary) setCreateErrors((current) => ({ ...current, summary: undefined })); }} /><ValidationMessage id="incident-summary-error">{createErrors.summary}</ValidationMessage></label>
              <div className="soc-modal-actions"><button className="soc-button secondary" type="button" disabled={mutation.loading} onClick={() => setCreateOpen(false)}>Cancel</button><button className="soc-button primary" type="submit" disabled={mutation.loading}>{mutation.loading ? "Creating…" : "Create incident"}</button></div>
            </form>
          </section>
        </div>
      )}

      {historyOpen && (
        <div className="soc-modal-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) closeHistory(); }}>
          <section className="soc-modal incident-history-modal" role="dialog" aria-modal="true" aria-labelledby="incident-history-title">
            <header><div><h2 id="incident-history-title">Incident history</h2><p>Search completed investigations and export the current result set.</p></div><button type="button" onClick={closeHistory} aria-label="Close incident history"><X size={18} /></button></header>
            <div className="incident-history-toolbar">
              <label className="filter-search"><Search size={16} /><span className="sr-only">Search incident history</span><input type="search" maxLength="200" value={historyQuery} onChange={(event) => setHistoryQuery(event.target.value)} placeholder="Search IDs, titles, assignees…" /></label>
              <button className="soc-button secondary" type="button" disabled={!historyRecords.length} onClick={() => downloadIncidentsCsv(historyRecords)}><Download size={15} />Export report</button>
            </div>
            <div className="incident-history-list" role="region" aria-label="Scrollable incident history" tabIndex="0">
              {historyRecords.map((incident) => (
                <article key={incident.id}>
                  <div><code>{incident.id}</code><StatusBadge status={incident.status} /></div>
                  <strong>{incident.title}</strong>
                  <p>{incident.summary}</p>
                  <footer><span>{incident.status === "false positive" ? "Marked false positive" : "Resolved"} by {incident.completedBy || "Unknown analyst"} · {incident.priority}</span><time>{formatIncidentUpdated(incident.completedAt || incident.updated)}</time></footer>
                </article>
              ))}
              {!historyRecords.length && <div className="table-empty"><History size={22} /><strong>No completed incidents match</strong><span>Clear the search or complete an investigation to add it to history.</span></div>}
            </div>
            <div className="soc-modal-actions"><span className="incident-history-count">{historyRecords.length} completed {historyRecords.length === 1 ? "incident" : "incidents"}</span><button className="soc-button secondary" type="button" onClick={closeHistory}>Done</button></div>
          </section>
        </div>
      )}

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
