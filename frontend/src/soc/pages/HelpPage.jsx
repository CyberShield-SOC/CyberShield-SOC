import { useMemo, useState } from "react";
import {
  Bot,
  BookOpen,
  CircleHelp,
  FileSearch,
  Keyboard,
  LockKeyhole,
  Search,
  Settings,
  ShieldAlert,
  Upload,
  Users,
} from "lucide-react";
import { SOC_ROUTES } from "../../hooks/useAuthRoute";
import { useSocWorkspace } from "../context/SocWorkspaceContext";
import { InlineNotice, PageHeader, Panel } from "../components/Ui";

const HELP_TOPICS = [
  {
    category: "Getting started",
    title: "Upload and parse security logs",
    description: "Import .log, .csv, .json, or .jsonl records and review the normalized events before investigation.",
    route: SOC_ROUTES.eventLogs,
    action: "Open Event Logs",
    icon: Upload,
  },
  {
    category: "Investigation",
    title: "Triage an alert",
    description: "Review severity, affected identity, detection logic, matched evidence, and recommended response actions.",
    route: SOC_ROUTES.alerts,
    action: "Open Alerts",
    icon: FileSearch,
  },
  {
    category: "Investigation",
    title: "Track an incident",
    description: "Assign ownership, change response status, follow the playbook, and record timestamped analyst notes.",
    route: SOC_ROUTES.incidentTracking,
    action: "Open Incident Tracking",
    icon: ShieldAlert,
  },
  {
    category: "Analysis",
    title: "Use AI-assisted analysis",
    description: "Ask evidence-grounded questions and review recommendations without granting autonomous response authority.",
    route: SOC_ROUTES.aiAnalysis,
    action: "Open AI Analysis",
    icon: Bot,
  },
  {
    category: "Administration",
    title: "Understand roles and permissions",
    description: "Compare Viewer, Analyst, and Admin access and learn which actions are enforced by the backend.",
    route: SOC_ROUTES.users,
    action: "Open Users",
    icon: Users,
    adminOnly: true,
  },
  {
    category: "Preferences",
    title: "Personalize the workspace",
    description: "Adjust theme, density, text size, contrast, and motion preferences.",
    route: SOC_ROUTES.settings,
    action: "Open Settings",
    icon: Settings,
  },
];

const ROLE_GUIDE = [
  ["Viewer", "Can inspect dashboards, events, alerts, incidents, notes, reports, and help content. All investigation changes are read-only."],
  ["Analyst", "Can upload logs, triage alerts, create and update incidents, and manage analyst notes."],
  ["Admin", "Has Analyst capabilities plus user management and workspace configuration."],
];

export default function HelpPage({ navigate }) {
  const { canAdminister, repositoryMode } = useSocWorkspace();
  const [query, setQuery] = useState("");
  const normalizedQuery = query.trim().toLowerCase();
  const visibleTopics = useMemo(() => HELP_TOPICS.filter((topic) => {
    if (topic.adminOnly && !canAdminister) return false;
    if (!normalizedQuery) return true;
    return `${topic.category} ${topic.title} ${topic.description}`.toLowerCase().includes(normalizedQuery);
  }), [canAdminister, normalizedQuery]);

  return (
    <div className="help-page">
      <PageHeader
        title="Help center"
        description="Guidance for monitoring, investigation, administration, and workspace accessibility."
      />

      <section className="help-hero" aria-labelledby="help-search-title">
        <span><CircleHelp size={22} aria-hidden="true" /></span>
        <div>
          <h2 id="help-search-title">How can we help?</h2>
          <p>Search the guides or open a workflow directly.</p>
          <label className="help-search">
            <Search size={17} aria-hidden="true" />
            <span className="sr-only">Search help topics</span>
            <input value={query} maxLength="80" onChange={(event) => setQuery(event.target.value)} placeholder="Search help topics…" />
            {query && <button type="button" onClick={() => setQuery("")}>Clear</button>}
          </label>
        </div>
      </section>

      <div className="help-layout">
        <Panel title="Guides and workflows" subtitle={`${visibleTopics.length} ${visibleTopics.length === 1 ? "guide" : "guides"} available`}>
          {visibleTopics.length ? (
            <div className="help-topic-grid">
              {visibleTopics.map((topic) => {
                const Icon = topic.icon;
                return (
                  <article key={topic.title}>
                    <span className="help-topic-icon"><Icon size={18} aria-hidden="true" /></span>
                    <div><small>{topic.category}</small><h3>{topic.title}</h3><p>{topic.description}</p></div>
                    <button className="soc-button secondary" type="button" onClick={() => navigate(topic.route)}>{topic.action}</button>
                  </article>
                );
              })}
            </div>
          ) : (
            <div className="help-empty"><Search size={22} /><strong>No matching guides</strong><p>Try a broader term such as alert, incident, role, or display.</p></div>
          )}
        </Panel>

        <aside className="help-aside">
          <Panel title="Quick reference" subtitle="Available throughout the SOC">
            <dl className="help-shortcuts">
              <div><dt><kbd>Ctrl/⌘ K</kbd></dt><dd>Focus global search</dd></div>
              <div><dt><kbd>/</kbd></dt><dd>Focus global search</dd></div>
              <div><dt><kbd>Esc</kbd></dt><dd>Close menus and popovers</dd></div>
              <div><dt><Keyboard size={15} /> <span>Tab</span></dt><dd>Move between controls</dd></div>
            </dl>
          </Panel>
          <Panel title="Data connection" subtitle="Know which behavior is authoritative">
            <InlineNotice tone={repositoryMode === "api" ? "success" : "info"} title={repositoryMode === "api" ? "Connected backend" : "Demo data mode"}>
              {repositoryMode === "api" ? "API permissions and stored investigation records are enforced by the connected service." : "This workspace is using sample records. Actions are retained only by the local demo environment."}
            </InlineNotice>
          </Panel>
        </aside>
      </div>

      <Panel className="help-role-panel" title="Roles and permissions" subtitle="The interface reflects permissions, while protected APIs remain the security boundary.">
        <div className="help-role-grid">
          {ROLE_GUIDE.map(([role, description], index) => (
            <article key={role}>
              <span>{index === 0 ? <BookOpen size={17} /> : index === 1 ? <ShieldAlert size={17} /> : <LockKeyhole size={17} />}</span>
              <div><strong>{role}</strong><p>{description}</p></div>
            </article>
          ))}
        </div>
      </Panel>
    </div>
  );
}
