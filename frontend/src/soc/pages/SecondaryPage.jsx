import { useMemo, useState } from "react";
import { CheckCircle2, ChevronRight, Search, SlidersHorizontal } from "lucide-react";
import { reportsPageContent } from "../data/mockData";
import { useSocWorkspace } from "../context/SocWorkspaceContext";
import { InlineNotice, PageHeader, Panel, StatCard, StatusBadge } from "../components/Ui";

export default function ReportsPage() {
  const { canAdminister, repositoryMode } = useSocWorkspace();
  const content = reportsPageContent;
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState(content.items[0]);
  const filtered = useMemo(
    () => content.items.filter((item) => item.toLowerCase().includes(query.toLowerCase())),
    [content.items, query],
  );
  const visibleSelected = filtered.includes(selected) ? selected : filtered[0] || null;

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
        <Panel title="Configuration details" subtitle={visibleSelected || "No item selected"}>
          {visibleSelected ? <div className="config-detail">
            <span className="config-detail-icon"><SlidersHorizontal size={20} /></span>
            <h3>{visibleSelected}</h3>
            <p>This frontend control is structured for server-backed configuration, validation, and audit history.</p>
            <dl><div><dt>State</dt><dd>Configured</dd></div><div><dt>Last reviewed</dt><dd>Today</dd></div><div><dt>Managed by</dt><dd>Security operations</dd></div></dl>
            <InlineNotice tone="info" title="Read-only configuration inventory">
              {!canAdminister
                ? "Your role can inspect this configuration but cannot change it."
                : repositoryMode === "api"
                  ? "The connected service does not expose a write endpoint for this configuration yet."
                  : "Configuration changes are disabled until a persistence endpoint is connected."}
            </InlineNotice>
          </div> : <div className="detail-placeholder"><Search size={24} /><strong>No matching configuration</strong><span>Clear the search to select an item.</span></div>}
        </Panel>
      </div>
    </>
  );
}
