import { useCallback, useEffect, useRef, useState } from "react";
import { RefreshCw, ScrollText, Search } from "lucide-react";
import { InlineNotice, PageHeader, Panel, StatusBadge } from "../components/Ui";
import { useSocWorkspace } from "../context/SocWorkspaceContext";
import { socRepository } from "../services/socRepository";
import {
  AUDIT_CATEGORY_OPTIONS,
  auditActionLabel,
  auditTargetLabel,
  summarizeAuditDetail,
} from "../utils/auditLog";

const PAGE_SIZE = 50;
const EMPTY_FILTERS = Object.freeze({ category: "", outcome: "", actor: "" });

function formatWhen(isoString) {
  if (!isoString) return "Unknown time";
  return new Date(isoString).toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export default function AuditLogPage() {
  const { repositoryMode } = useSocWorkspace();
  const [filters, setFilters] = useState(EMPTY_FILTERS);
  const [events, setEvents] = useState([]);
  const [nextBeforeId, setNextBeforeId] = useState(null);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState("");
  // A slow response for an old filter must not overwrite a newer one.
  const requestVersion = useRef(0);

  const load = useCallback(async (activeFilters) => {
    const version = ++requestVersion.current;
    setLoading(true);
    setError("");
    try {
      const page = await socRepository.getAuditEvents({ ...activeFilters, limit: PAGE_SIZE });
      if (version !== requestVersion.current) return;
      setEvents(page.events);
      setNextBeforeId(page.nextBeforeId);
    } catch (loadError) {
      if (version !== requestVersion.current) return;
      setError(loadError.message || "The audit log could not be loaded.");
    } finally {
      if (version === requestVersion.current) setLoading(false);
    }
  }, []);

  // Typing in the actor box waits for a pause; the selects apply at once.
  useEffect(() => {
    const delay = window.setTimeout(() => load(filters), 250);
    return () => window.clearTimeout(delay);
  }, [filters, load]);

  async function loadOlder() {
    if (!nextBeforeId || loadingMore) return;
    const version = requestVersion.current;
    setLoadingMore(true);
    try {
      const page = await socRepository.getAuditEvents({ ...filters, beforeId: nextBeforeId, limit: PAGE_SIZE });
      if (version !== requestVersion.current) return;
      setEvents((current) => [...current, ...page.events]);
      setNextBeforeId(page.nextBeforeId);
    } catch (loadError) {
      setError(loadError.message || "Older audit events could not be loaded.");
    } finally {
      setLoadingMore(false);
    }
  }

  const filtered = Boolean(filters.category || filters.outcome || filters.actor);

  return (
    <>
      <PageHeader
        title="Audit log"
        description="Who signed in, and who changed accounts, rules, feeds, and models. Entries are written by the server and cannot be edited or removed here."
        actions={<button className="soc-button secondary" type="button" disabled={loading} onClick={() => load(filters)}><RefreshCw size={15} />Refresh</button>}
      />

      {repositoryMode !== "api" && (
        <InlineNotice tone="info" title="Sample entries">
          These rows are illustrative. Connect the backend to see the real trail for your workspace.
        </InlineNotice>
      )}
      {error && <InlineNotice tone="error" title="Audit log unavailable">{error}</InlineNotice>}

      <section className="filter-bar audit-filter-bar" aria-label="Audit log filters">
        <label className="filter-search"><Search size={16} /><span className="sr-only">Filter by person</span><input type="search" maxLength="100" value={filters.actor} onChange={(event) => setFilters((current) => ({ ...current, actor: event.target.value }))} placeholder="Filter by person…" /></label>
        <label><span className="sr-only">Area</span><select value={filters.category} onChange={(event) => setFilters((current) => ({ ...current, category: event.target.value }))}><option value="">All areas</option>{AUDIT_CATEGORY_OPTIONS.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}</select></label>
        <label><span className="sr-only">Outcome</span><select value={filters.outcome} onChange={(event) => setFilters((current) => ({ ...current, outcome: event.target.value }))}><option value="">All outcomes</option><option value="success">Succeeded</option><option value="failure">Failed</option></select></label>
      </section>

      <Panel
        title="Recorded actions"
        subtitle={loading ? "Loading…" : `${events.length} shown, newest first${nextBeforeId ? " · older entries available" : ""}`}
        actions={filtered ? <button className="soc-text-button" type="button" onClick={() => setFilters(EMPTY_FILTERS)}>Clear filters</button> : null}
      >
        <div className="soc-table-scroll audit-table-wrap" role="region" aria-label="Scrollable audit log" tabIndex="0" aria-busy={loading}>
          <table className="soc-table audit-table">
            <thead><tr><th>When</th><th>Who</th><th>Action</th><th>On</th><th>Outcome</th><th>From</th></tr></thead>
            <tbody>
              {events.map((event) => {
                const detailLines = summarizeAuditDetail(event.detail);
                return (
                  <tr key={event.id}>
                    <td className="mono">{formatWhen(event.occurredAt)}</td>
                    <td><strong>{event.actorName}</strong>{event.actorRole && <small>{event.actorRole}</small>}</td>
                    <td><strong>{auditActionLabel(event.action)}</strong>{detailLines.length > 0 && <small title={detailLines.join("\n")}>{detailLines.join(" · ")}</small>}</td>
                    <td>{auditTargetLabel(event) || <span className="audit-none">Not applicable</span>}</td>
                    <td><StatusBadge status={event.outcome === "failure" ? "failed" : "success"} /></td>
                    <td className="mono">{event.ipAddress || <span className="audit-none">Unknown</span>}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          {!loading && !events.length && (
            <div className="table-empty">
              <ScrollText size={22} />
              <strong>{filtered ? "No entries match these filters" : "Nothing recorded yet"}</strong>
              <span>{filtered ? "Clear a filter to widen the view." : "Sign-ins and administrative changes appear here as they happen."}</span>
            </div>
          )}
        </div>
        {nextBeforeId && (
          <div className="audit-load-more">
            <button className="soc-button secondary" type="button" disabled={loadingMore} onClick={loadOlder}>
              {loadingMore ? <span className="soc-spinner small" /> : null}{loadingMore ? "Loading…" : "Load older entries"}
            </button>
          </div>
        )}
      </Panel>
    </>
  );
}
