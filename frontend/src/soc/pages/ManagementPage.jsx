import { useMemo, useState } from "react";
import { ArrowRight, Database, FileClock, Network, RefreshCw, Search, Settings, ShieldCheck, Users } from "lucide-react";
import { SOC_ROUTES } from "../../hooks/useAuthRoute";
import { InlineNotice, PageHeader, Panel, StatCard, StatusBadge } from "../components/Ui";
import { useSocWorkspace } from "../context/SocWorkspaceContext";
import { formatTimestamp } from "../utils/eventUtils";
import { isTerminalIncidentStatus } from "../utils/incidentWorkflow";

function buildConnectors(events) {
  const connectors = new Map();
  events.forEach((event) => {
    const name = String(event.source || "Unknown source").trim() || "Unknown source";
    const current = connectors.get(name) || { name, count: 0, failed: 0, ips: new Set(), latest: null };
    current.count += 1;
    if (event.status === "failed") current.failed += 1;
    if (event.sourceIp && String(event.sourceIp).toLowerCase() !== "unknown") current.ips.add(event.sourceIp);
    const timestamp = new Date(event.timestamp || event.ingestedAt).getTime();
    if (Number.isFinite(timestamp) && (!current.latest || timestamp > current.latest)) current.latest = timestamp;
    connectors.set(name, current);
  });
  return [...connectors.values()].map((connector) => ({ ...connector, ips: connector.ips.size })).sort((left, right) => right.count - left.count);
}

function ManageWorkspace({ navigate }) {
  const { alerts, apiHealth, canAdminister, events, incidents, notes, repositoryMode, settings, refreshAll } = useSocWorkspace();
  const activeIncidents = incidents.filter((incident) => !isTerminalIncidentStatus(incident.status)).length;
  const apiOperational = ["ok", "demo"].includes(apiHealth?.status);
  const controls = [
    { icon: Database, title: "Data ingestion", value: `${events.length.toLocaleString()} records`, detail: "Upload files and inspect normalized telemetry.", route: SOC_ROUTES.eventLogs },
    { icon: ShieldCheck, title: "Incident governance", value: `${activeIncidents} active`, detail: "Review investigations, status, evidence, and history.", route: SOC_ROUTES.incidents },
    { icon: Users, title: "User access", value: canAdminister ? "Admin controls" : "Role policy", detail: canAdminister ? "Manage roles and enabled accounts." : "Review workspace access guidance.", route: canAdminister ? SOC_ROUTES.users : SOC_ROUTES.help },
    { icon: Settings, title: "Workspace configuration", value: settings?.workspace?.name || "CyberShield SOC", detail: "Manage supported workspace and appearance preferences.", route: SOC_ROUTES.settings },
  ];
  return (
    <>
      <PageHeader title="Manage" description="Operate the connected workspace through supported, auditable workflows." actions={<button className="soc-button secondary" type="button" onClick={refreshAll}><RefreshCw size={15} />Refresh workspace</button>} />
      <div className="soc-stats-grid">
        <StatCard label="Normalized events" value={events.length.toLocaleString()} trend="Available telemetry" />
        <StatCard label="Active alerts" value={alerts.filter((alert) => !["resolved", "contained"].includes(alert.status)).length} trend="Current investigation queue" tone="critical" />
        <StatCard label="Active incidents" value={activeIncidents} trend={`${incidents.length - activeIncidents} completed`} />
        <StatCard label="Analyst notes" value={notes.length} trend="Persisted investigation context" tone="success" />
      </div>
      <Panel title="Workspace operations" subtitle="Select a control to continue in its dedicated workflow">
        <div className="management-card-grid">
          {controls.map(({ icon: Icon, ...control }) => <button type="button" key={control.title} onClick={() => navigate(control.route)}><span><Icon size={18} /></span><div><small>{control.title}</small><strong>{control.value}</strong><p>{control.detail}</p></div><ArrowRight size={16} /></button>)}
        </div>
      </Panel>
      <Panel title="Environment health" subtitle="Live service and persistence status">
        <div className="management-health-grid"><div><span>API service</span><StatusBadge status={apiOperational ? "operational" : "offline"} /></div><div><span>Repository</span><strong>{repositoryMode === "api" ? "Connected backend" : "Sample workspace"}</strong></div><div><span>Last service response</span><strong>{formatTimestamp(apiHealth?.timestamp)}</strong></div><div><span>Workspace</span><strong>{settings?.workspace?.name || "CyberShield SOC"}</strong></div></div>
      </Panel>
    </>
  );
}

function IntegrationsWorkspace({ navigate }) {
  const { apiHealth, events, refresh, resources } = useSocWorkspace();
  const connectors = useMemo(() => buildConnectors(events), [events]);
  const [query, setQuery] = useState("");
  const [selectedName, setSelectedName] = useState(null);
  const filtered = connectors.filter((connector) => connector.name.toLowerCase().includes(query.trim().toLowerCase()));
  const selected = connectors.find((connector) => connector.name === selectedName) || filtered[0] || null;
  const failed = events.filter((event) => event.status === "failed").length;
  const loading = resources.events.loading || resources.alerts.loading;
  const apiOperational = ["ok", "demo"].includes(apiHealth?.status);

  function refreshTelemetry() {
    return Promise.all([refresh("events"), refresh("alerts"), refresh("dashboard"), refresh("health")]);
  }

  return (
    <>
      <PageHeader title="Integrations" description="Inspect the telemetry sources currently represented by persisted backend records." actions={<button className="soc-button secondary" type="button" disabled={loading} onClick={refreshTelemetry}><RefreshCw size={15} />Refresh telemetry</button>} />
      <div className="soc-stats-grid">
        <StatCard label="Connected sources" value={connectors.length} trend="Detected from telemetry" tone="success" />
        <StatCard label="Event records" value={events.length.toLocaleString()} trend="Latest available dataset" />
        <StatCard label="Failed outcomes" value={failed.toLocaleString()} trend="Requires analyst review" tone={failed ? "critical" : "success"} />
        <StatCard label="API service" value={apiOperational ? "Online" : "Unavailable"} trend={formatTimestamp(apiHealth?.timestamp)} tone={apiOperational ? "success" : "critical"} />
      </div>
      <div className="secondary-workspace integrations-workspace">
        <Panel title="Telemetry connectors" subtitle={`${filtered.length} of ${connectors.length} sources`}>
          <label className="secondary-search"><Search size={16} /><span className="sr-only">Search telemetry connectors</span><input type="search" maxLength="200" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search source names…" /></label>
          <div className="integration-card-list">
            {filtered.map((connector) => <button type="button" key={connector.name} className={selected?.name === connector.name ? "selected" : ""} onClick={() => setSelectedName(connector.name)}><span><Network size={17} /></span><div><strong>{connector.name}</strong><small>{connector.count.toLocaleString()} events · {connector.ips} unique IPs</small></div><StatusBadge status="operational" /></button>)}
            {!filtered.length && <div className="table-empty"><Search size={22} /><strong>No sources match</strong><span>Adjust the search or ingest telemetry from a supported source.</span></div>}
          </div>
        </Panel>
        <Panel title="Connector details" subtitle={selected?.name || "No telemetry source selected"}>
          {selected ? <div className="integration-detail"><span className="config-detail-icon"><Network size={20} /></span><h3>{selected.name}</h3><p>This connector is derived from persisted normalized event records and refreshes with the workspace dataset.</p><dl><div><dt>Records</dt><dd>{selected.count.toLocaleString()}</dd></div><div><dt>Failed outcomes</dt><dd>{selected.failed.toLocaleString()}</dd></div><div><dt>Unique IPs</dt><dd>{selected.ips.toLocaleString()}</dd></div><div><dt>Latest record</dt><dd>{selected.latest ? formatTimestamp(selected.latest) : "Unknown time"}</dd></div></dl><InlineNotice tone="info" title="Read-only connector inventory">Connection provisioning requires a backend integration endpoint. Current controls refresh and inspect real telemetry without simulating unsupported writes.</InlineNotice><div className="integration-detail-actions"><button className="soc-button primary" type="button" onClick={() => navigate(SOC_ROUTES.eventLogs)}><FileClock size={15} />View event records</button><button className="soc-button secondary" type="button" disabled={loading} onClick={refreshTelemetry}><RefreshCw size={15} />Refresh source</button></div></div> : <div className="detail-placeholder"><Network size={24} /><strong>No connector data</strong><span>Upload or ingest a log source to populate this workspace.</span></div>}
        </Panel>
      </div>
    </>
  );
}

export default function ManagementPage({ navigate, route }) {
  return route === SOC_ROUTES.integrations ? <IntegrationsWorkspace navigate={navigate} /> : <ManageWorkspace navigate={navigate} />;
}
