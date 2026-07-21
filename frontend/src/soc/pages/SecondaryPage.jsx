import { useMemo, useState } from "react";
import { CheckCircle2, ChevronRight, Download, FileText, Search } from "lucide-react";
import { reportsPageContent } from "../data/mockData";
import { useSocWorkspace } from "../context/SocWorkspaceContext";
import { downloadAlertsCsv, downloadEventsCsv, downloadIncidentsCsv } from "../utils/eventUtils";
import { InlineNotice, PageHeader, Panel, StatCard, StatusBadge } from "../components/Ui";

const REPORT_EXPORTERS = Object.freeze({
  "Daily SOC operations": {
    description: "Every normalized event record currently ingested into the workspace.",
    recordLabel: "events",
    getRecords: ({ events }) => events,
    download: ({ events }) => downloadEventsCsv(events),
  },
  "Weekly incident summary": {
    description: "Every tracked incident with its owner, priority, and current status.",
    recordLabel: "incidents",
    getRecords: ({ incidents }) => incidents,
    download: ({ incidents }) => downloadIncidentsCsv(incidents),
  },
  "Detection coverage": {
    description: "Every alert the detection engine has generated, by rule.",
    recordLabel: "alerts",
    getRecords: ({ alerts }) => alerts,
    download: ({ alerts }) => downloadAlertsCsv(alerts, "detection-coverage"),
  },
  "Executive risk overview": {
    description: "Current alerts ranked by risk, highest first.",
    recordLabel: "alerts",
    getRecords: ({ alerts }) => alerts,
    download: ({ alerts }) => downloadAlertsCsv(
      [...alerts].sort((left, right) => Number(right.risk || 0) - Number(left.risk || 0)),
      "executive-risk-overview",
    ),
  },
});

export default function ReportsPage() {
  const { alerts, events, incidents } = useSocWorkspace();
  const content = reportsPageContent;
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState(content.items[0]);
  const filtered = useMemo(
    () => content.items.filter((item) => item.toLowerCase().includes(query.toLowerCase())),
    [content.items, query],
  );
  const visibleSelected = filtered.includes(selected) ? selected : filtered[0] || null;
  const exporter = visibleSelected ? REPORT_EXPORTERS[visibleSelected] : null;
  const reportData = useMemo(() => ({ events, alerts, incidents }), [events, alerts, incidents]);
  const recordCount = exporter ? exporter.getRecords(reportData).length : 0;
  const canDownload = Boolean(exporter && recordCount);

  return (
    <>
      <PageHeader
        title={content.title}
        description={content.description}
      />
      <div className="soc-stats-grid">
        {content.stats.map(([label, value], index) => <StatCard key={label} label={label} value={value} trend={index === 0 ? "Current workspace" : "Updated live"} tone={index === 2 ? "success" : "default"} />)}
      </div>
      <div className="secondary-workspace">
        <Panel title={`${content.title} workspace`} subtitle={`${content.items.length} configured items`}>
          <label className="secondary-search"><Search size={16} /><span className="sr-only">Search items</span><input type="search" maxLength="200" value={query} onChange={(event) => setQuery(event.target.value)} placeholder={`Search ${content.title.toLowerCase()}…`} /></label>
          <div className="config-list">
            {filtered.map((item, index) => (
              <button type="button" key={item} className={visibleSelected === item ? "selected" : ""} onClick={() => setSelected(item)}>
                <span className="config-icon"><CheckCircle2 size={17} /></span>
                <span><strong>{item}</strong><small>{index % 2 ? "Operational and monitored" : "Configured for this workspace"}</small></span>
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
              <div><dt>Records available</dt><dd>{recordCount.toLocaleString()} {exporter?.recordLabel || ""}</dd></div>
              <div><dt>Managed by</dt><dd>Security operations</dd></div>
            </dl>
            <div className="config-detail-actions">
              <button
                type="button"
                className="soc-button primary"
                disabled={!canDownload}
                onClick={() => exporter?.download(reportData)}
              >
                <Download size={15} /> Download CSV
              </button>
            </div>
            {!canDownload && (
              <InlineNotice tone="info" title={exporter ? "Nothing to export yet" : "Export not available"}>
                {exporter
                  ? `No ${exporter.recordLabel} are available in this workspace yet. Upload a log file or generate activity first.`
                  : "This report has no connected dataset yet."}
              </InlineNotice>
            )}
          </div> : <div className="detail-placeholder"><Search size={24} /><strong>No matching configuration</strong><span>Clear the search to select an item.</span></div>}
        </Panel>
      </div>
    </>
  );
}
