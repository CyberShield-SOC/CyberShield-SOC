import { useId, useMemo, useRef, useState } from "react";
import {
  Archive,
  Clock3,
  Database,
  FilePlus2,
  Filter,
  History,
  Link2,
  Pin,
  RefreshCw,
  Save,
  Search,
  Trash2,
  X,
} from "lucide-react";
import { SOC_ROUTES } from "../../hooks/useAuthRoute";
import { useSocWorkspace } from "../context/SocWorkspaceContext";
import { formatTimestamp } from "../utils/eventUtils";
import { parseNoteTags, validateAnalystNote } from "../utils/formValidation";
import { ErrorState, LoadingState, PageHeader, Panel, StatusBadge, ValidationMessage } from "../components/Ui";

function NoteEditor({ apiMode = false, disabled = false, incidents = [], initialNote, onCancel, onSave }) {
  const [title, setTitle] = useState(initialNote?.title || "");
  const [body, setBody] = useState(initialNote?.body || "");
  const [tags, setTags] = useState(initialNote?.tags?.join(", ") || "");
  const [linkedType, setLinkedType] = useState(initialNote?.linkedType || (apiMode ? "incident" : "workspace"));
  const [linkedId, setLinkedId] = useState(initialNote?.linkedId || (apiMode ? incidents[0]?.id || "" : ""));
  const [errors, setErrors] = useState({});
  const [submitting, setSubmitting] = useState(false);
  const messageId = useId();
  const titleRef = useRef(null);
  const bodyRef = useRef(null);
  const tagsRef = useRef(null);
  const linkedIdRef = useRef(null);
  const titleErrorId = `${messageId}-title-error`;
  const bodyErrorId = `${messageId}-body-error`;
  const tagsErrorId = `${messageId}-tags-error`;
  const linkedIdErrorId = `${messageId}-linked-id-error`;

  function clearError(field) {
    setErrors((current) => ({ ...current, [field]: undefined }));
  }

  async function submit(event) {
    event.preventDefault();
    if (submitting || disabled) return;
    const nextErrors = {
      ...validateAnalystNote({ title, body, tags }),
      linkedId: apiMode && !String(linkedId || "").trim()
        ? "Select the incident this note belongs to."
        : undefined,
    };
    setErrors(nextErrors);

    if (nextErrors.title) {
      titleRef.current?.focus();
      return;
    }
    if (nextErrors.body) {
      bodyRef.current?.focus();
      return;
    }
    if (nextErrors.tags) {
      tagsRef.current?.focus();
      return;
    }
    if (nextErrors.linkedId) {
      linkedIdRef.current?.focus();
      return;
    }

    setSubmitting(true);
    try {
      await onSave({
        title: title.trim(),
        body: body.trim(),
        tags: parseNoteTags(tags),
        linkedType,
        linkedId: String(linkedId || "").trim(),
      });
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form className="note-editor" onSubmit={submit} noValidate>
      <label className={errors.title ? "has-error" : undefined}>
        Title
        <input ref={titleRef} value={title} onChange={(event) => { setTitle(event.target.value); if (errors.title) clearError("title"); }} maxLength="100" autoFocus aria-invalid={Boolean(errors.title)} aria-describedby={errors.title ? titleErrorId : undefined} />
        <ValidationMessage id={titleErrorId}>{errors.title}</ValidationMessage>
      </label>
      <label className={errors.body ? "has-error" : undefined}>
        Investigation note
        <textarea ref={bodyRef} value={body} onChange={(event) => { setBody(event.target.value); if (errors.body) clearError("body"); }} maxLength="4000" rows="9" placeholder="Record observations, evidence, decisions, and next steps…" aria-invalid={Boolean(errors.body)} aria-describedby={errors.body ? bodyErrorId : undefined} />
        <ValidationMessage id={bodyErrorId}>{errors.body}</ValidationMessage>
      </label>
      <label className={errors.tags ? "has-error" : undefined}>Tags<input ref={tagsRef} value={tags} onChange={(event) => { setTags(event.target.value); if (errors.tags) clearError("tags"); }} maxLength="246" placeholder="identity, containment, handoff" aria-invalid={Boolean(errors.tags)} aria-describedby={errors.tags ? tagsErrorId : undefined} /><ValidationMessage id={tagsErrorId}>{errors.tags}</ValidationMessage></label>
      <div className="note-link-grid">
        <label>Link type<select value={linkedType} disabled={apiMode} onChange={(event) => setLinkedType(event.target.value)}>{!apiMode && <option value="workspace">Workspace</option>}<option value="incident">Incident</option>{!apiMode && <option value="alert">Alert</option>}{!apiMode && <option value="event">Event</option>}</select></label>
        {apiMode ? (
          <label className={errors.linkedId ? "has-error" : undefined}>Linked incident<select ref={linkedIdRef} value={linkedId} onChange={(event) => { setLinkedId(event.target.value); if (errors.linkedId) clearError("linkedId"); }} aria-invalid={Boolean(errors.linkedId)} aria-describedby={errors.linkedId ? linkedIdErrorId : undefined}><option value="">Select an incident</option>{incidents.map((incident) => <option key={incident.id} value={incident.id}>{incident.id} - {incident.title}</option>)}</select><ValidationMessage id={linkedIdErrorId}>{errors.linkedId}</ValidationMessage></label>
        ) : (
          <label>Linked ID<input value={linkedId} onChange={(event) => setLinkedId(event.target.value)} maxLength="40" placeholder="INC-1042" /></label>
        )}
      </div>
      <div className="note-editor-actions"><button className="soc-button secondary" type="button" onClick={onCancel} disabled={submitting || disabled}>Cancel</button><button className="soc-button primary" type="submit" disabled={submitting || disabled}><Save size={15} />{submitting || disabled ? "Saving…" : "Save note"}</button></div>
    </form>
  );
}

export default function AnalystNotesPage({ navigate }) {
  const {
    alerts,
    canWrite,
    events,
    notes,
    incidents,
    repositoryMode,
    mutation,
    storage,
    resources,
    refresh,
    setGlobalTimeRange,
    setSelectedAlertId,
    setSelectedEventId,
    setSelectedIncidentId,
    addNote,
    deleteNote,
    updateNote,
  } = useSocWorkspace();
  const [query, setQuery] = useState("");
  const [tag, setTag] = useState("");
  const [linkType, setLinkType] = useState("");
  const [showArchived, setShowArchived] = useState(false);
  const [selectedId, setSelectedId] = useState(null);
  const [editing, setEditing] = useState(false);
  const [creating, setCreating] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState(null);
  const { error, loading } = resources.notes;
  const apiMode = repositoryMode === "api";

  const tags = useMemo(() => [...new Set(notes.flatMap((note) => note.tags))].sort(), [notes]);
  const filtered = useMemo(() => notes
    .filter((note) => {
      const searchText = `${note.id} ${note.title} ${note.body} ${note.author} ${note.linkedId} ${note.tags.join(" ")}`.toLowerCase();
      return (
        (showArchived ? note.archived : !note.archived) &&
        (!query || searchText.includes(query.toLowerCase())) &&
        (!tag || note.tags.includes(tag)) &&
        (!linkType || note.linkedType === linkType)
      );
    })
    .sort((a, b) => Number(b.pinned) - Number(a.pinned) || new Date(b.updatedAt) - new Date(a.updatedAt)), [linkType, notes, query, showArchived, tag]);
  const selected = filtered.find((note) => note.id === selectedId) || filtered[0] || null;
  const linkedRecordAvailable = !selected || selected.linkedType === "workspace" || ({
    incident: incidents.some((incident) => incident.id === selected.linkedId),
    alert: alerts.some((alert) => alert.id === selected.linkedId),
    event: events.some((event) => event.id === selected.linkedId),
  }[selected.linkedType] ?? false);
  const storagePercent = Math.min((storage.used / storage.limit) * 100, 100);

  if (loading) return <LoadingState label="Loading analyst notes and version history…" />;
  if (error) return <ErrorState message={error} onRetry={() => refresh("notes")} />;

  async function saveNew(input) {
    if (await addNote(input)) setCreating(false);
  }

  async function saveEdit(input) {
    if (await updateNote(selected.id, input)) setEditing(false);
  }

  async function confirmDelete() {
    if (!deleteTarget) return;
    if (await deleteNote(deleteTarget.id)) {
      setSelectedId(null);
      setEditing(false);
      setDeleteTarget(null);
    }
  }

  function openLinkedRecord() {
    if (!selected || !linkedRecordAvailable) return;
    const routeByType = {
      incident: SOC_ROUTES.incidents,
      alert: SOC_ROUTES.alerts,
      event: SOC_ROUTES.eventLogs,
      workspace: SOC_ROUTES.dashboard,
    };
    setGlobalTimeRange("all");
    if (selected.linkedType === "incident") setSelectedIncidentId(selected.linkedId);
    if (selected.linkedType === "alert") setSelectedAlertId(selected.linkedId);
    if (selected.linkedType === "event") setSelectedEventId(selected.linkedId);
    navigate(routeByType[selected.linkedType] || SOC_ROUTES.dashboard);
  }

  return (
    <>
      <PageHeader
        title="Analyst Notes"
        description={apiMode ? "Keep incident-linked investigation notes, tags, and storage visibility in one workspace." : "Keep linked investigation notes, tags, storage visibility, and revision history in one workspace."}
        actions={<><button className="soc-button secondary" type="button" disabled={mutation.loading} onClick={() => refresh("notes")}><RefreshCw size={15} />Refresh</button><button className="soc-button primary" type="button" disabled={!canWrite || mutation.loading || (apiMode && !incidents.length)} title={!canWrite ? "Viewer access is read-only." : apiMode && !incidents.length ? "Create an incident before adding a connected analyst note." : undefined} onClick={() => setCreating(true)}><FilePlus2 size={15} />New note</button></>}
      />

      <div className="notes-overview">
        <article><span><Database size={17} />{apiMode ? "Authenticated note storage" : "Session draft storage"}</span><strong>{(storage.used / 1024).toFixed(1)} KB <small>loaded</small></strong><div><i style={{ width: `${storagePercent}%` }} /></div><p>{apiMode ? "Notes are stored in PostgreSQL and remain scoped to their incident." : "Mock mode stores notes only in this browser tab."}</p></article>
        <article><span><History size={17} />Revision history</span><strong>{notes.reduce((sum, note) => sum + note.versions.length, 0)} <small>versions</small></strong><p>{apiMode ? "The connected API currently exposes the latest saved version of each note." : "Every content or lifecycle change creates a timestamped history entry."}</p></article>
        <article><span><Link2 size={17} />Linked records</span><strong>{notes.filter((note) => note.linkedType !== "workspace").length} <small>notes</small></strong><p>Incident, alert, and event links keep investigation context discoverable.</p></article>
      </div>

      <section className="filter-bar notes-filter-bar" aria-label="Note filters">
        <label className="filter-search"><Search size={16} /><span className="sr-only">Search notes</span><input type="search" maxLength="200" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search notes, tags, linked IDs…" /></label>
        <label><span className="sr-only">Tag</span><select value={tag} onChange={(event) => setTag(event.target.value)}><option value="">All tags</option>{tags.map((item) => <option key={item}>{item}</option>)}</select></label>
        <label><span className="sr-only">Linked record type</span><select value={linkType} onChange={(event) => setLinkType(event.target.value)}><option value="">All link types</option><option value="incident">Incident</option><option value="alert">Alert</option><option value="event">Event</option><option value="workspace">Workspace</option></select></label>
        <button className={`soc-button secondary ${showArchived ? "active" : ""}`} type="button" onClick={() => setShowArchived((current) => !current)}><Archive size={15} />{showArchived ? "Show active" : "Show archived"}</button>
        <button className="soc-button secondary" type="button" onClick={() => { setQuery(""); setTag(""); setLinkType(""); }}><Filter size={15} />Clear</button>
      </section>

      <div className="notes-workspace">
        <Panel title={showArchived ? "Archived notes" : "Active notes"} subtitle={`${filtered.length} matching notes`}>
          <div className="note-list" role="region" aria-label="Scrollable analyst note list" tabIndex="0">
            {filtered.map((note) => (
              <button type="button" key={note.id} className={selected?.id === note.id ? "selected" : ""} onClick={() => { setSelectedId(note.id); setEditing(false); }}>
                <div className="note-list-title"><strong>{note.title}</strong>{note.pinned && <Pin size={13} fill="currentColor" />}</div>
                <p>{note.body}</p>
                <div className="note-tags">{note.tags.map((item) => <span key={item}>{item}</span>)}</div>
                <footer><span>{note.author} · {formatTimestamp(note.updatedAt)}</span><code>{note.linkedId}</code></footer>
              </button>
            ))}
            {!filtered.length && <div className="table-empty"><Search size={22} /><strong>No notes match this view</strong><span>Change filters or create a new analyst note.</span></div>}
          </div>
        </Panel>

        <div className="note-detail-stack" role="region" aria-label="Scrollable analyst note details" tabIndex="0">
          <Panel title={selected?.id || "Note details"} actions={selected && <StatusBadge status={selected.archived ? "archived" : "active"} />}>
            {selected ? editing ? (
              <NoteEditor apiMode={apiMode} disabled={mutation.loading} incidents={incidents} initialNote={selected} onCancel={() => setEditing(false)} onSave={saveEdit} />
            ) : (
              <article className="note-detail">
                <div className="note-detail-title"><div><h2>{selected.title}</h2><span>Updated {formatTimestamp(selected.updatedAt)} by {selected.author}</span></div><button type="button" disabled={mutation.loading || !canWrite} className={selected.pinned ? "active" : ""} onClick={() => updateNote(selected.id, { pinned: !selected.pinned })} aria-label={selected.pinned ? "Unpin note" : "Pin note"}><Pin size={16} fill={selected.pinned ? "currentColor" : "none"} /></button></div>
                <p className="note-body">{selected.body}</p>
                <div className="note-tags">{selected.tags.map((item) => <span key={item}>{item}</span>)}</div>
                <button className="linked-record" type="button" disabled={!linkedRecordAvailable} title={!linkedRecordAvailable ? "This linked record is no longer available in the workspace." : undefined} onClick={openLinkedRecord}><Link2 size={15} /><span><small>Linked {selected.linkedType}</small><strong>{selected.linkedId}</strong></span><span>{linkedRecordAvailable ? "Open" : "Unavailable"}</span></button>
                <div className="note-detail-actions"><button className="soc-button danger" type="button" disabled={mutation.loading || !canWrite} onClick={() => setDeleteTarget(selected)}><Trash2 size={15} />Delete</button><button className="soc-button secondary" type="button" disabled={mutation.loading || !canWrite} onClick={() => updateNote(selected.id, { archived: !selected.archived })}><Archive size={15} />{selected.archived ? "Restore" : "Archive"}</button><button className="soc-button primary" type="button" disabled={mutation.loading || !canWrite} onClick={() => setEditing(true)}>Edit note</button></div>
              </article>
            ) : <div className="detail-placeholder"><FilePlus2 size={24} /><strong>Select or create a note</strong><span>Link durable analyst context to security records.</span></div>}
          </Panel>

          {selected && <Panel title="Version history" subtitle={`${selected.versions.length} recorded versions`}><ol className="note-history">{[...selected.versions].reverse().map((version) => <li key={version.version}><span><Clock3 size={14} /></span><div><strong>Version {version.version} · {version.summary}</strong><p>{formatTimestamp(version.at)} by {version.author}</p></div></li>)}</ol></Panel>}
        </div>
      </div>

      {creating && <div className="soc-modal-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget && !mutation.loading) setCreating(false); }}><section className="soc-modal note-modal" role="dialog" aria-modal="true" aria-labelledby="new-note-title"><header><div><h2 id="new-note-title">New analyst note</h2><p>Record evidence-backed context. Avoid passwords, tokens, and unnecessary personal data.</p></div><button type="button" disabled={mutation.loading} onClick={() => setCreating(false)} aria-label="Close"><X size={18} /></button></header><NoteEditor apiMode={apiMode} disabled={mutation.loading} incidents={incidents} onCancel={() => setCreating(false)} onSave={saveNew} /></section></div>}
      {deleteTarget && <div className="soc-modal-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget && !mutation.loading) setDeleteTarget(null); }}><section className="soc-modal confirmation-modal" role="alertdialog" aria-modal="true" aria-labelledby="delete-note-title" aria-describedby="delete-note-description"><header><div><h2 id="delete-note-title">Delete analyst note?</h2><p id="delete-note-description">“{deleteTarget.title}” and its displayed history will be permanently removed.</p></div><button type="button" disabled={mutation.loading} onClick={() => setDeleteTarget(null)} aria-label="Close"><X size={18} /></button></header><div className="soc-modal-actions"><button className="soc-button secondary" type="button" disabled={mutation.loading} onClick={() => setDeleteTarget(null)}>Cancel</button><button className="soc-button danger" type="button" disabled={mutation.loading} onClick={confirmDelete}><Trash2 size={15} />{mutation.loading ? "Deleting…" : "Delete note"}</button></div></section></div>}
    </>
  );
}
