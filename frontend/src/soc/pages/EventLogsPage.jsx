import { useEffect, useMemo, useRef, useState } from "react";
import { Bot, ChevronLeft, ChevronRight, Database, Download, Files, FileUp, RefreshCw, Search, X } from "lucide-react";
import { SOC_ROUTES } from "../../hooks/useAuthRoute";
import { useSocWorkspace } from "../context/SocWorkspaceContext";
import { socRepository } from "../services/socRepository";
import {
  downloadEventsCsv,
  filterEvents,
  formatTimestamp,
  inspectLogFile,
  validateLogFile,
} from "../utils/eventUtils";
import { nextIncidentId } from "../utils/recordIds";
import { paginateRecords } from "../utils/pagination";
import { getIncidentActionLabel } from "../utils/alertRecommendations";
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
} from "../components/Ui";

const PAGE_SIZE = 10;
const HISTORY_PAGE_SIZE = 25;

function initialQuery() {
  const queryString = window.location.hash.split("?", 2)[1] || "";
  return (new URLSearchParams(queryString).get("q") || "").slice(0, 200);
}

export default function EventLogsPage({ navigate }) {
  const {
    canWrite,
    currentActor,
    createIncident,
    events: latestEvents,
    timeFilteredEvents: timeFilteredLatestEvents,
    incidents,
    mutation,
    repositoryMode,
    resources,
    refresh,
    setGlobalTimeRange,
    selectedEventId,
    setSelectedEventId,
    setSelectedIncidentId,
    uploadLogFile,
  } = useSocWorkspace();
  const { error, loading } = resources.events;
  const [filters, setFilters] = useState({ query: initialQuery(), severity: "", status: "", source: "" });
  const [page, setPage] = useState(1);
  const [fileResult, setFileResult] = useState(null);
  const [fileError, setFileError] = useState("");
  const [historyOpen, setHistoryOpen] = useState(false);
  const [uploadHistory, setUploadHistory] = useState([]);
  const [historyPagination, setHistoryPagination] = useState({ page: 1, pageSize: HISTORY_PAGE_SIZE, total: 0, pageCount: 1 });
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyError, setHistoryError] = useState("");
  const [historyQueryDraft, setHistoryQueryDraft] = useState("");
  const [historyQuery, setHistoryQuery] = useState("");
  const [historySelectionId, setHistorySelectionId] = useState("");
  const [selectedUploadBatch, setSelectedUploadBatch] = useState(null);
  const [dataSyncLoading, setDataSyncLoading] = useState(false);
  const [dataSyncError, setDataSyncError] = useState("");
  const [dataSyncMessage, setDataSyncMessage] = useState("");
  const [isCsvDragActive, setIsCsvDragActive] = useState(false);
  const historyRequestId = useRef(0);

  useEffect(() => {
    function syncGlobalSearch() {
      setFilters((current) => ({ ...current, query: initialQuery() }));
    }

    window.addEventListener("hashchange", syncGlobalSearch);
    return () => window.removeEventListener("hashchange", syncGlobalSearch);
  }, []);

  useEffect(() => {
    if (!dataSyncMessage) return undefined;
    const timeoutId = window.setTimeout(() => setDataSyncMessage(""), 4200);
    return () => window.clearTimeout(timeoutId);
  }, [dataSyncMessage]);

  const allEvents = selectedUploadBatch?.events || latestEvents || [];
  const visibleTimeRangeEvents = selectedUploadBatch ? allEvents : timeFilteredLatestEvents || [];
  const filteredEvents = useMemo(
    () => filterEvents(visibleTimeRangeEvents, filters),
    [visibleTimeRangeEvents, filters],
  );
  const pagination = useMemo(() => paginateRecords(filteredEvents, page, PAGE_SIZE), [filteredEvents, page]);
  const pageEvents = pagination.items;
  const sources = useMemo(
    () => [...new Set((allEvents || []).map((event) => event.source).filter(Boolean))].sort(),
    [allEvents],
  );
  // Detail selection follows the analyst, not the visible table page. This
  // keeps linked-note navigation and pagination from discarding context.
  const selectedEvent = allEvents.find((event) => event.id === selectedEventId) || null;
  const linkedIncident = selectedEvent
    ? incidents.find((incident) => (
      incident.sourceAlertId === selectedEvent.sourceAlertId
      || incident.eventIds.includes(selectedEvent.id)
    ))
    : null;

  function updateFilter(key, value) {
    setFilters((current) => ({ ...current, [key]: value }));
  }

  useEffect(() => {
    setPage(1);
  }, [filters.query, filters.severity, filters.source, filters.status]);

  async function ingestFile(file, { allowedExtensions } = {}) {
    setFileError("");
    try {
      if (repositoryMode === "api") {
        validateLogFile(file, {
          allowedExtensions: allowedExtensions || [".log", ".csv", ".json", ".jsonl"],
          maxBytes: 10 * 1024 * 1024,
        });
        const result = await uploadLogFile(file);
        setSelectedUploadBatch(null);
        setSelectedEventId(null);
        setDataSyncError("");
        setDataSyncMessage("The uploaded file is now the latest database batch.");
        setFileResult({
          name: file.name,
          records: result.parsing?.stored_entries || 0,
          skipped: result.parsing?.skipped_lines || 0,
          format: result.parsing?.format || "log",
          uploaded: true,
        });
      } else {
        if (allowedExtensions) validateLogFile(file, { allowedExtensions });
        setFileResult(await inspectLogFile(file));
      }
    } catch (inspectionError) {
      setFileResult(null);
      setFileError(inspectionError.message);
    }
  }

  async function handleFile(event) {
    const file = event.target.files?.[0];
    if (!file) return;
    try {
      await ingestFile(file);
    } finally {
      event.target.value = "";
    }
  }

  async function handleCsvFile(event) {
    const file = event.target.files?.[0];
    if (!file) return;
    try {
      await ingestFile(file, { allowedExtensions: [".csv"] });
    } finally {
      event.target.value = "";
    }
  }

  function handleCsvDragOver(event) {
    event.preventDefault();
    if (!mutation.loading && canWrite) setIsCsvDragActive(true);
  }

  function handleCsvDragLeave() {
    setIsCsvDragActive(false);
  }

  async function handleCsvDrop(event) {
    event.preventDefault();
    setIsCsvDragActive(false);
    if (mutation.loading || !canWrite) return;
    const file = event.dataTransfer.files?.[0];
    if (!file) return;
    await ingestFile(file, { allowedExtensions: [".csv"] });
  }

  async function loadUploadHistory(nextPage = 1, nextQuery = historyQuery) {
    const requestId = historyRequestId.current + 1;
    historyRequestId.current = requestId;
    setHistoryLoading(true);
    setHistoryError("");
    try {
      const result = await socRepository.getUploadHistory({
        page: nextPage,
        pageSize: HISTORY_PAGE_SIZE,
        query: nextQuery,
      });
      if (historyRequestId.current !== requestId) return;
      setUploadHistory(result.uploads);
      setHistoryPagination(result.pagination);
    } catch (historyRequestError) {
      if (historyRequestId.current !== requestId) return;
      setUploadHistory([]);
      setHistoryError(historyRequestError.message || "Upload history could not be loaded.");
    } finally {
      if (historyRequestId.current === requestId) setHistoryLoading(false);
    }
  }

  function openUploadHistory() {
    setHistoryOpen(true);
    void loadUploadHistory(1);
  }

  function searchUploadHistory(event) {
    event.preventDefault();
    const nextQuery = historyQueryDraft.trim().slice(0, 100);
    setHistoryQuery(nextQuery);
    void loadUploadHistory(1, nextQuery);
  }

  function clearUploadHistorySearch() {
    setHistoryQueryDraft("");
    setHistoryQuery("");
    void loadUploadHistory(1, "");
  }

  async function selectUploadBatch(upload) {
    if (historySelectionId) return;
    setHistorySelectionId(upload.uploadId);
    setHistoryError("");
    try {
      const batch = await socRepository.getUploadBatch(upload.uploadId);
      setSelectedUploadBatch(batch);
      setSelectedEventId(null);
      setFilters({ query: "", severity: "", status: "", source: "" });
      setPage(1);
      setHistoryOpen(false);
      setDataSyncError("");
      setDataSyncMessage(`${batch.filename} loaded from database history.`);
    } catch (batchError) {
      setHistoryError(batchError.message || "That uploaded file could not be loaded.");
    } finally {
      setHistorySelectionId("");
    }
  }

  async function pullLatestData() {
    if (dataSyncLoading) return;
    setDataSyncLoading(true);
    setDataSyncError("");
    setDataSyncMessage("");
    try {
      const latest = await refresh("events");
      if (latest === null) throw new Error("Latest database events could not be loaded.");
      await Promise.all([refresh("alerts"), refresh("dashboard")]);
      setSelectedUploadBatch(null);
      setSelectedEventId(null);
      setGlobalTimeRange("all");
      setPage(1);
      setDataSyncMessage("Latest database event logs are now in view.");
    } catch (syncError) {
      setDataSyncError(syncError.message || "Latest database events could not be loaded.");
    } finally {
      setDataSyncLoading(false);
    }
  }

  async function promoteSelectedEvent() {
    if (!selectedEvent) return;
    if (linkedIncident) {
      setSelectedIncidentId(linkedIncident.id);
      setGlobalTimeRange("all");
      navigate(SOC_ROUTES.incidents);
      return;
    }

    const created = await createIncident({
      id: nextIncidentId(incidents),
      title: selectedEvent.event,
      owner: currentActor,
      priority: selectedEvent.severity,
      status: "open",
      updated: "Just now",
      sla: selectedEvent.severity === "critical" ? "5m acknowledge target" : "30m acknowledge target",
      summary: selectedEvent.message,
      eventIds: [selectedEvent.id],
      sourceAlertId: selectedEvent.sourceAlertId,
    });
    if (created) {
      setSelectedIncidentId(created.id);
      navigate(SOC_ROUTES.incidents);
    }
  }

  if (loading) return <LoadingState label="Loading normalized event records…" />;
  if (error) return <ErrorState message={error} onRetry={() => refresh("events")} />;

  const failedCount = allEvents.filter((event) => event.status === "failed").length;

  return (
    <>
      <PageHeader
        title="Event Logs"
        description="Upload, parse, search, and review normalized security events."
        actions={<>
          <button className="soc-button secondary" type="button" onClick={openUploadHistory}><Files size={15} />File history</button>
          <button
            className="soc-button secondary"
            type="button"
            onClick={pullLatestData}
            disabled={dataSyncLoading || mutation.loading || repositoryMode !== "api"}
            title={repositoryMode !== "api" ? "Connect the backend to pull database events." : "Sync and show the latest persisted upload batch."}
          >
            {dataSyncLoading ? <RefreshCw size={15} className="spinning" /> : <Database size={15} />}
            Pull latest data
          </button>
          <label className={`soc-button primary file-button${mutation.loading || !canWrite ? " disabled" : ""}`} title={!canWrite ? "Viewer access is read-only." : undefined}>
            <FileUp size={15} /> {repositoryMode === "api" ? "Upload log file" : "Inspect log file"}
            <input
              type="file"
              disabled={mutation.loading || !canWrite}
              accept={repositoryMode === "api" ? ".log,.csv,.json,.jsonl,text/plain,text/csv,application/json,application/x-ndjson" : ".log,.txt,.csv,.json,.jsonl,text/plain,text/csv,application/json,application/x-ndjson"}
              onChange={handleFile}
            />
          </label>
        </>}
      />

      {dataSyncError && (
        <InlineNotice
          tone="error"
          title="Data sync failed"
          onDismiss={() => setDataSyncError("")}
        >
          {dataSyncError}
        </InlineNotice>
      )}

      {dataSyncMessage && (
        <InlineNotice
          className="event-sync-toast"
          tone="success"
          title="Event data updated"
          onDismiss={() => setDataSyncMessage("")}
        >
          {dataSyncMessage}
        </InlineNotice>
      )}

      {selectedUploadBatch && (
        <InlineNotice className="historical-upload-notice" tone="info" title={`Viewing ${selectedUploadBatch.filename}`}>
          Historical upload from {formatTimestamp(selectedUploadBatch.uploadedAt)} · {selectedUploadBatch.events.length.toLocaleString()} event records. The global time filter is paused until you pull the latest data.
        </InlineNotice>
      )}

      <div className="soc-stats-grid">
        <StatCard label="Records available" value={allEvents.length.toLocaleString()} trend={`${filteredEvents.length} match time and page filters`} />
        <StatCard label="Sources connected" value={sources.length} trend={sources.join(", ")} />
        <StatCard label="Failed events" value={failedCount} trend="Review authentication failures" tone="critical" />
        <StatCard label="Parser health" value="99.7%" trend="12 patterns actively normalized" tone="success" />
      </div>

      {(fileResult || fileError) && (
        <InlineNotice
          className="file-notice"
          tone={fileError ? "error" : "success"}
          title={fileError ? "File could not be ingested" : `${fileResult.name} was ingested`}
          onDismiss={() => { setFileResult(null); setFileError(""); }}
        >
          {fileError || (fileResult.uploaded
            ? `${fileResult.records.toLocaleString()} ${fileResult.format.toUpperCase()} records were stored and analyzed. ${fileResult.skipped ? `${fileResult.skipped} malformed record${fileResult.skipped === 1 ? " was" : "s were"} skipped. ` : ""}Showing all imported timestamps.`
            : `${fileResult.records.toLocaleString()} non-empty records · local preview only; no data was uploaded`)}
        </InlineNotice>
      )}

      <Panel
        title="Upload CSV"
        subtitle={repositoryMode === "api"
          ? "Drag a CSV file here or browse to parse, store, and analyze new events."
          : "Drag a CSV file here to preview it locally. Connect the backend to persist uploads."}
      >
        <div
          className={`csv-dropzone${isCsvDragActive ? " active" : ""}${mutation.loading || !canWrite ? " disabled" : ""}`}
          onDragOver={handleCsvDragOver}
          onDragLeave={handleCsvDragLeave}
          onDrop={handleCsvDrop}
        >
          <FileUp size={26} aria-hidden="true" />
          <strong>Drag &amp; drop a CSV file here</strong>
          <span>or</span>
          <label
            className={`soc-button primary file-button${mutation.loading || !canWrite ? " disabled" : ""}`}
            title={!canWrite ? "Viewer access is read-only." : undefined}
          >
            Browse CSV file
            <input
              type="file"
              accept=".csv,text/csv"
              disabled={mutation.loading || !canWrite}
              onChange={handleCsvFile}
            />
          </label>
          <small>Only .csv files are accepted here, up to 10 MB.</small>
        </div>
      </Panel>

      <section className="filter-bar" aria-label="Event filters">
        <label className="filter-search"><Search size={16} /><span className="sr-only">Search events</span><input type="search" maxLength="200" value={filters.query} onChange={(event) => updateFilter("query", event.target.value)} placeholder="Search logs, IPs, users…" /></label>
        <label><span className="sr-only">Severity</span><select value={filters.severity} onChange={(event) => updateFilter("severity", event.target.value)}><option value="">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="info">Info</option></select></label>
        <label><span className="sr-only">Status</span><select value={filters.status} onChange={(event) => updateFilter("status", event.target.value)}><option value="">All statuses</option><option value="failed">Failed</option><option value="blocked">Blocked</option><option value="review">Review</option><option value="contained">Contained</option><option value="success">Success</option></select></label>
        <label><span className="sr-only">Source</span><select value={filters.source} onChange={(event) => updateFilter("source", event.target.value)}><option value="">All sources</option>{sources.map((source) => <option key={source}>{source}</option>)}</select></label>
        <button className="soc-button secondary" type="button" onClick={() => downloadEventsCsv(filteredEvents)} disabled={!filteredEvents.length}><Download size={15} />Export CSV</button>
      </section>

      <div className="event-workspace">
        <Panel
          title={selectedUploadBatch ? `Events from ${selectedUploadBatch.filename}` : "Latest database event records"}
          subtitle={`${filteredEvents.length} of ${allEvents.length} records${selectedUploadBatch ? " · historical upload" : " · latest upload"}${filteredEvents.length > PAGE_SIZE ? ` · page ${pagination.page} of ${pagination.pageCount}` : ""}`}
          actions={filters.query || filters.severity || filters.status || filters.source ? <button className="soc-text-button" type="button" onClick={() => setFilters({ query: "", severity: "", status: "", source: "" })}>Clear filters</button> : null}
        >
          <div className={`soc-table-scroll events-table-wrap${filteredEvents.length > PAGE_SIZE ? " with-pagination" : ""}`} role="region" aria-label="Scrollable event log" tabIndex="0">
            <table className="soc-table events-table">
              <thead><tr><th>Timestamp</th><th>Source</th><th>Source IP</th><th>User</th><th>Event</th><th>Severity</th><th>Status</th></tr></thead>
              <tbody>
                {pageEvents.map((event) => (
                  <tr key={event.id} onClick={() => setSelectedEventId(event.id)} className={selectedEvent?.id === event.id ? "selected" : ""} tabIndex="0" onKeyDown={(keyboardEvent) => { if (keyboardEvent.key === "Enter" || keyboardEvent.key === " ") { keyboardEvent.preventDefault(); setSelectedEventId(event.id); } }}>
                    <td className="mono">{formatTimestamp(event.timestamp)}</td>
                    <td>{event.source}</td>
                    <td className="mono">{event.sourceIp}</td>
                    <td className="mono">{event.user}</td>
                    <td><strong>{event.event}</strong><small>{event.id}</small></td>
                    <td><SeverityBadge severity={event.severity} /></td>
                    <td><StatusBadge status={event.status} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
            {!filteredEvents.length && <div className="table-empty"><Search size={22} /><strong>{filters.query || filters.severity || filters.status || filters.source ? "No events match these filters" : "No events in this time range"}</strong><span>{filters.query || filters.severity || filters.status || filters.source ? "Adjust the search or clear a filter to continue." : "Choose a longer global time range or ingest recent telemetry."}</span></div>}
          </div>
          <TablePagination label="events" page={pagination.page} pageSize={PAGE_SIZE} totalItems={filteredEvents.length} onPageChange={setPage} />
        </Panel>

        <aside className={`event-detail ${selectedEvent ? "open" : ""}`} aria-label="Scrollable selected event details" tabIndex="0">
          {selectedEvent ? (
            <>
              <header><div><SeverityBadge severity={selectedEvent.severity} /><span>{selectedEvent.id}</span></div><button type="button" onClick={() => setSelectedEventId(null)} aria-label="Close event details"><X size={17} /></button></header>
              <h2>{selectedEvent.event}</h2>
              <p>{selectedEvent.message}</p>
              <RiskMeter value={selectedEvent.risk} />
              <dl>
                <div><dt>Rule</dt><dd>{selectedEvent.rule}</dd></div>
                <div><dt>Source</dt><dd>{selectedEvent.source}</dd></div>
                <div><dt>Source IP</dt><dd className="mono">{selectedEvent.sourceIp}</dd></div>
                <div><dt>User</dt><dd className="mono">{selectedEvent.user}</dd></div>
                <div><dt>Observed</dt><dd>{formatTimestamp(selectedEvent.timestamp)}</dd></div>
                <div><dt>Status</dt><dd><StatusBadge status={selectedEvent.status} /></dd></div>
              </dl>
              <button className="soc-button primary full" type="button" onClick={() => navigate(SOC_ROUTES.aiAnalysis)}><Bot size={16} />Analyze with AI</button>
              <button
                className="soc-button secondary full"
                type="button"
                onClick={promoteSelectedEvent}
                disabled={(!linkedIncident && !canWrite) || mutation.loading || (repositoryMode === "api" && !selectedEvent.sourceAlertId && !linkedIncident)}
                title={!linkedIncident && !canWrite
                  ? "Viewer access is read-only."
                  : repositoryMode === "api" && !selectedEvent.sourceAlertId
                    ? "Only events matched to a persisted alert can create an incident."
                    : undefined}
              >
                {linkedIncident || selectedEvent.sourceAlertId || repositoryMode !== "api"
                  ? getIncidentActionLabel(linkedIncident, selectedEvent.severity)
                  : "No matched alert"}
              </button>
            </>
          ) : (
            <div className="detail-placeholder"><Search size={24} /><strong>Select an event</strong><span>Review normalized fields, risk, and investigation actions.</span></div>
          )}
        </aside>
      </div>

      {historyOpen && (
        <div className="soc-modal-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget && !historyLoading && !historySelectionId) setHistoryOpen(false); }}>
          <section className="soc-modal file-history-modal" role="dialog" aria-modal="true" aria-labelledby="file-history-title">
            <header>
              <div><h2 id="file-history-title">Uploaded file history</h2><p>Search and select a persisted batch to inspect its event logs.</p></div>
              <button type="button" disabled={historyLoading || Boolean(historySelectionId)} onClick={() => setHistoryOpen(false)} aria-label="Close file history"><X size={18} /></button>
            </header>
            <div className="file-history-summary">
              <span><Files size={16} aria-hidden="true" /></span>
              <div><strong>{historyPagination.total.toLocaleString()} {historyQuery ? "matching " : ""}uploaded {historyPagination.total === 1 ? "file" : "files"}</strong><small>{repositoryMode === "api" ? "Stored as parsed event batches in PostgreSQL" : "Persistent history requires the connected backend"}</small></div>
              <button className="soc-icon-button" type="button" disabled={historyLoading || Boolean(historySelectionId)} onClick={() => loadUploadHistory(historyPagination.page)} aria-label="Refresh file history"><RefreshCw size={15} className={historyLoading ? "spinning" : ""} /></button>
            </div>
            <form className="file-history-search" role="search" onSubmit={searchUploadHistory}>
              <label>
                <Search size={15} aria-hidden="true" />
                <span className="sr-only">Search uploaded files</span>
                <input
                  type="search"
                  maxLength="100"
                  value={historyQueryDraft}
                  onChange={(event) => setHistoryQueryDraft(event.target.value)}
                  placeholder="Search filename or format…"
                  disabled={historyLoading || Boolean(historySelectionId)}
                />
              </label>
              {historyQuery && <button className="soc-button secondary" type="button" onClick={clearUploadHistorySearch} disabled={historyLoading || Boolean(historySelectionId)}>Clear</button>}
              <button className="soc-button secondary" type="submit" disabled={historyLoading || Boolean(historySelectionId)}>Search</button>
            </form>
            {historyError && <InlineNotice tone="error" title="File history unavailable">{historyError}</InlineNotice>}
            <div className="file-history-list" role="region" aria-label="Scrollable uploaded file history" tabIndex="0" aria-busy={historyLoading || Boolean(historySelectionId)}>
              {historyLoading && !uploadHistory.length ? <LoadingState label="Loading file history…" /> : uploadHistory.map((upload, index) => (
                <article
                  key={upload.uploadId}
                  className={historySelectionId === upload.uploadId ? "loading" : ""}
                  role="button"
                  tabIndex="0"
                  aria-label={`View event logs from ${upload.filename}`}
                  aria-current={selectedUploadBatch?.uploadId === upload.uploadId ? "true" : undefined}
                  onClick={() => selectUploadBatch(upload)}
                  onKeyDown={(event) => {
                    if (event.key === "Enter" || event.key === " ") {
                      event.preventDefault();
                      void selectUploadBatch(upload);
                    }
                  }}
                >
                  <header><div><strong>{upload.filename}</strong><code>{upload.uploadId}</code></div>{historyPagination.page === 1 && index === 0 && !historyQuery ? <span>Latest</span> : selectedUploadBatch?.uploadId === upload.uploadId ? <span>Selected</span> : null}</header>
                  <dl>
                    <div><dt>Format</dt><dd>{upload.format.toUpperCase()}</dd></div>
                    <div><dt>Events</dt><dd>{upload.storedEntries.toLocaleString()}</dd></div>
                    <div><dt>Alerts</dt><dd>{upload.storedAlerts.toLocaleString()}</dd></div>
                    <div><dt>Ingested</dt><dd>{formatTimestamp(upload.uploadedAt)}</dd></div>
                  </dl>
                  <span className="file-history-open">{historySelectionId === upload.uploadId ? "Loading events…" : "View event logs →"}</span>
                </article>
              ))}
              {!historyLoading && !historyError && !uploadHistory.length && <div className="table-empty"><Files size={22} /><strong>{historyQuery ? "No uploaded files match this search" : "No uploaded files yet"}</strong><span>{historyQuery ? "Try a different filename or clear the search." : "Upload a supported log file to create the first persistent ingestion batch."}</span></div>}
            </div>
            <div className="soc-modal-actions file-history-actions">
              <span>Page {historyPagination.page} of {historyPagination.pageCount}</span>
              <div>
                <button className="soc-button secondary" type="button" disabled={historyLoading || Boolean(historySelectionId) || historyPagination.page <= 1} onClick={() => loadUploadHistory(historyPagination.page - 1)}><ChevronLeft size={15} />Previous</button>
                <button className="soc-button secondary" type="button" disabled={historyLoading || Boolean(historySelectionId) || historyPagination.page >= historyPagination.pageCount} onClick={() => loadUploadHistory(historyPagination.page + 1)}>Next<ChevronRight size={15} /></button>
              </div>
            </div>
          </section>
        </div>
      )}
    </>
  );
}
