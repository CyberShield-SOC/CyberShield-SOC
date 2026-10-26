import { useMemo, useState } from "react";
import { CheckCircle2, ChevronRight, Download, FileText, Search } from "lucide-react";
import { reportsPageContent } from "../data/mockData";
import { useSocWorkspace } from "../context/SocWorkspaceContext";
import { downloadCsvFile } from "../utils/eventUtils";
import { createReportExport, REPORT_EXPORTERS } from "../utils/reportExport";
import { InlineNotice, PageHeader, Panel, StatCard, StatusBadge } from "../components/Ui";

export default function ReportsPage() {
  const { alerts, events, incidents, resources, canExportReports, repositoryMode, refresh } = useSocWorkspace();
  const content = reportsPageContent;
  const [exportState, setExportState] = useState({ loading: false, error: "", message: "" });
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState(content.items[0]);
  const filtered = useMemo(
    () => content.items.filter((item) => item.toLowerCase().includes(query.toLowerCase())),
    [content.items, query],
  );
  const visibleSelected = filtered.includes(selected) ? selected : filtered[0] || null;
  const exporter = visibleSelected ? REPORT_EXPORTERS[visibleSelected] : null;
  const reportData = useMemo(() => ({ events, alerts, incidents }), [events, alerts, incidents]);
  const recordCount = exporter ? (reportData[exporter.key] || []).length : 0;
  const resource = resources[exporter?.key] || {};
  const canDownload = Boolean(canExportReports && exporter && recordCount && !resource.loading && !resource.error && !exportState.loading);

  async function exportReport() {
    if (!canDownload) return;
    const reportName = visibleSelected;
    setExportState({ loading: true, error: "", message: "" });
    try {
      await new Promise((resolve) => window.requestAnimationFrame(resolve));
      const result = createReportExport(reportName, reportData);
      downloadCsvFile(result.csv, result.filename);
      setExportState({ loading: false, error: "", message: `Download started: ${result.filename} (${result.recordCount.toLocaleString()} records).` });
    } catch (error) {
      setExportState({ loading: false, error: error.message || "The report could not be downloaded. Try again.", message: "" });
    }
  }

  return (
    <>
      <PageHeader
        title={content.title}
        description={content.description}
      />
      <div className="soc-stats-grid">
        {[["Reports available", content.items.length], ["Loaded events", events.length], ["Loaded incidents", incidents.length], ["Loaded alerts", alerts.length]].map(([label, value]) => <StatCard key={label} label={label} value={value.toLocaleString()} trend={repositoryMode === "api" ? "Connected workspace" : "Sample workspace"} />)}
      </div>
      <div className="secondary-workspace">
        <Panel title={`${content.title} workspace`} subtitle={`${content.items.length} configured items`}>
          <label className="secondary-search"><Search size={16} /><span className="sr-only">Search items</span><input type="search" maxLength="200" value={query} onChange={(event) => setQuery(event.target.value)} placeholder={`Search ${content.title.toLowerCase()}…`} /></label>
          <div className="config-list">
            {filtered.map((item) => (
              <button type="button" key={item} className={visibleSelected === item ? "selected" : ""} onClick={() => { setSelected(item); setExportState({ loading: false, error: "", message: "" }); }} disabled={exportState.loading}>
                <span className="config-icon"><CheckCircle2 size={17} /></span>
                <span><strong>{item}</strong><small>{REPORT_EXPORTERS[item].key === "events" ? "Latest loaded upload" : "Loaded workspace records"}</small></span>
                <StatusBadge status="configured" />
                <ChevronRight size={16} />
              </button>
            ))}
            {!filtered.length && <div className="table-empty"><Search size={22} /><strong>No configured items match</strong><span>Clear or adjust the search to restore the list.</span></div>}
          </div>
        </Panel>
        <Panel title="Report details" subtitle={visibleSelected || "No item selected"}>
          {visibleSelected ? <div className="config-detail">
            <span className="config-detail-icon"><FileText size={20} /></span>
            <h3>{visibleSelected}</h3>
            <p>{exporter?.description || "This report is not yet wired to a downloadable dataset."}</p>
            <dl>
              <div><dt>State</dt><dd>Configured</dd></div>
              <div><dt>Records available</dt><dd>{recordCount.toLocaleString()} {exporter?.key || ""}</dd></div>
              <div><dt>Scope</dt><dd>{exporter?.key === "events" ? "Latest loaded upload" : "All loaded workspace records"}</dd></div>
              <div><dt>Format</dt><dd>CSV</dd></div>
            </dl>
            <div className="config-detail-actions">
              <button
                type="button"
                className="soc-button primary"
                disabled={!canDownload}
                onClick={exportReport}
              >
                <Download size={15} /> {exportState.loading ? "Preparing download…" : "Export report"}
              </button>
            </div>
            {exportState.error && <InlineNotice tone="error" title="Export failed">{exportState.error}</InlineNotice>}
            {exportState.message && <InlineNotice tone="success" title="Report ready">{exportState.message}</InlineNotice>}
            {resource.loading && <p role="status">Loading report records…</p>}
            {resource.error && <InlineNotice tone="error" title="Report data unavailable">{resource.error}<button className="soc-text-button" type="button" onClick={() => refresh(exporter.key)}>Retry report data</button></InlineNotice>}
            {!canExportReports && <InlineNotice title="Export unavailable">Your role cannot export workspace reports.</InlineNotice>}
            {!recordCount && !resource.loading && !resource.error && (
              <InlineNotice tone="info" title={exporter ? "Nothing to export yet" : "Export not available"}>
                {exporter
                  ? `No ${exporter.key} are available in this workspace yet. Upload a log file or generate activity first.`
                  : "This report has no connected dataset yet."}
              </InlineNotice>
            )}
          </div> : <div className="detail-placeholder"><Search size={24} /><strong>No matching configuration</strong><span>Clear the search to select an item.</span></div>}
        </Panel>
      </div>
    </>
  );
}
