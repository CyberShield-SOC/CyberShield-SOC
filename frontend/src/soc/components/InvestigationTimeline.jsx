import { useState } from "react";
import { Clock3 } from "lucide-react";
import { formatTimestamp } from "../utils/eventUtils";
import { paginateRecords } from "../utils/pagination";
import { TablePagination } from "./Ui";

export function InvestigationTimeline({ items = [], loading, error, onRetry }) {
  const [page, setPage] = useState(1);
  const pagination = paginateRecords(items, page, 10);
  return <>
    {loading && <p role="status">Loading recorded history…</p>}
    {error && <div role="alert"><p>{error}</p>{onRetry && <button className="soc-text-button" type="button" onClick={onRetry}>Retry history</button>}</div>}
    <ol className="timeline-list compact investigation-history">
      {pagination.items.map((item) => <li key={item.id}><Clock3 size={16} aria-hidden="true" /><div>
        <strong>{item.title}</strong><span>{formatTimestamp(item.at)}{item.actor ? ` · ${item.actor}` : ""}</span>
        {item.actor ? <>
          {item.reason && <p><b>Reason:</b> {item.reason}</p>}
          {item.note && <p className="history-note"><b>Note:</b> {item.note}</p>}
          {item.changes?.length > 0 && <dl>{item.changes.map((change) => <div key={change.label}><dt>{change.label}</dt><dd>{change.before} → {change.after}</dd></div>)}</dl>}
        </> : <p>{item.detail}</p>}
      </div></li>)}
    </ol>
    {!loading && !error && !items.length && <p className="empty-inline">No recorded changes yet.</p>}
    <div className="history-pagination"><TablePagination label="history entries" page={pagination.page} pageSize={10} totalItems={items.length} onPageChange={setPage} /></div>
  </>;
}

export function ResolutionDetails({ incident }) {
  if (!incident || !["resolved", "false positive"].includes(incident.status)) return null;
  return <section className="incident-resolution-details" aria-label="Resolution details">
    <h4>Resolution details</h4>
    <dl>
      <div><dt>Outcome</dt><dd>{incident.status === "false positive" ? "False positive" : "Resolved"}</dd></div>
      <div><dt>Reason</dt><dd>{incident.resolutionReason && incident.resolutionReason !== "LEGACY_UNKNOWN" ? incident.resolutionReason : "Not recorded for this historical incident"}</dd></div>
      <div><dt>Resolution note</dt><dd className="history-note">{incident.resolutionNote || "Not recorded"}</dd></div>
      <div><dt>Resolved by</dt><dd>{incident.completedBy || "Unknown analyst"}</dd></div>
      <div><dt>Completed</dt><dd>{formatTimestamp(incident.completedAt)}</dd></div>
    </dl>
  </section>;
}
