import { useMemo, useState } from "react";
import {
  Activity,
  Clock3,
  RefreshCw,
  Search,
  ShieldCheck,
  Target,
} from "lucide-react";
import {
  CURRENT_DETECTION_RULE_IDS,
  summarizeRuleActivity,
} from "../data/detectionRulePack";
import { useSocWorkspace } from "../context/SocWorkspaceContext";
import {
  ErrorState,
  InlineNotice,
  LoadingState,
  PageHeader,
  Panel,
  SeverityBadge,
  StatCard,
  StatusBadge,
} from "../components/Ui";
import { formatTimestamp } from "../utils/eventUtils";

export default function ThreatDetectionPage() {
  const {
    alerts,
    detectionRules,
    repositoryMode,
    refresh,
    resources,
  } = useSocWorkspace();
  const [query, setQuery] = useState("");
  const [selectedId, setSelectedId] = useState(CURRENT_DETECTION_RULE_IDS[0]);

  const rules = useMemo(() => CURRENT_DETECTION_RULE_IDS.map((ruleId) => ({
    ...detectionRules[ruleId],
    activity: summarizeRuleActivity(ruleId, alerts),
  })), [alerts, detectionRules]);
  const filtered = useMemo(() => {
    const term = query.trim().toLowerCase();
    if (!term) return rules;
    return rules.filter((rule) => [
      rule.id,
      rule.engineKey,
      rule.name,
      rule.description,
      rule.technique,
      rule.criteria,
    ].join(" ").toLowerCase().includes(term));
  }, [query, rules]);
  const selected = filtered.find((rule) => rule.id === selectedId) || filtered[0] || null;
  const totalMatches = rules.reduce((total, rule) => total + rule.activity.total, 0);
  const activeMatches = rules.reduce((total, rule) => total + rule.activity.active, 0);
  const triggeredRules = rules.filter((rule) => rule.activity.total > 0).length;

  if (resources.alerts.loading && !alerts.length) {
    return <LoadingState label="Loading detection rule activity…" />;
  }
  if (resources.alerts.error && !alerts.length) {
    return <ErrorState message={resources.alerts.error} onRetry={() => refresh("alerts")} />;
  }

  return (
    <>
      <PageHeader
        title="Threat Detection"
        description="Review the built-in rules that run automatically when log files are parsed."
        actions={(
          <button
            className="soc-button secondary"
            type="button"
            disabled={resources.alerts.loading}
            onClick={() => refresh("alerts")}
          >
            <RefreshCw size={15} className={resources.alerts.loading ? "spin" : ""} />
            Refresh activity
          </button>
        )}
      />

      <div className="soc-stats-grid">
        <StatCard label="Enabled rules" value={String(rules.length)} trend="Built into DetectionEngine" tone="success" />
        <StatCard label="Rules triggered" value={String(triggeredRules)} trend={`${rules.length - triggeredRules} without loaded matches`} />
        <StatCard label="Generated alerts" value={String(totalMatches)} trend="Current alert collection" />
        <StatCard label="Active matches" value={String(activeMatches)} trend="Not closed or resolved" tone={activeMatches ? "critical" : "success"} />
      </div>

      <InlineNotice className="rule-pack-notice" title="How the rule pack runs" tone="info">
        Accepted uploads are normalized into security events, all three rules inspect the parsed batch, and matching alerts are saved with their evidence line numbers. Rule configuration is read-only because the current API does not expose a rule-management endpoint.
      </InlineNotice>

      <div className="secondary-workspace detection-rule-workspace">
        <Panel title="Current rule pack" subtitle={`${rules.length} backend-implemented rules`}>
          <label className="secondary-search">
            <Search size={16} />
            <span className="sr-only">Search detection rules</span>
            <input
              type="search"
              maxLength="120"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search rule ID, technique, or behavior…"
            />
          </label>
          <div className="config-list detection-rule-list">
            {filtered.map((rule) => (
              <button
                type="button"
                key={rule.id}
                className={selected?.id === rule.id ? "selected" : ""}
                onClick={() => setSelectedId(rule.id)}
              >
                <span className="config-icon"><ShieldCheck size={17} /></span>
                <span>
                  <strong>{rule.id} · {rule.name}</strong>
                  <small>{rule.criteria}</small>
                </span>
                <SeverityBadge severity={rule.severity} />
                <span className="rule-match-count">{rule.activity.total} match{rule.activity.total === 1 ? "" : "es"}</span>
              </button>
            ))}
            {!filtered.length && (
              <div className="table-empty">
                <Search size={22} />
                <strong>No detection rules match</strong>
                <span>Clear or adjust the search to restore the rule pack.</span>
              </div>
            )}
          </div>
        </Panel>

        <Panel title="Rule details" subtitle={selected ? `${selected.id} · ${selected.engineKey}` : "No rule selected"}>
          {selected ? (
            <div className="config-detail detection-rule-detail">
              <span className="config-detail-icon"><Target size={20} /></span>
              <div className="rule-detail-title">
                <div>
                  <h3>{selected.name}</h3>
                  <p>{selected.description}</p>
                </div>
                <StatusBadge status={selected.status} />
              </div>
              <dl>
                <div><dt>Severity</dt><dd><SeverityBadge severity={selected.severity} /></dd></div>
                <div><dt>ATT&amp;CK</dt><dd>{selected.technique}</dd></div>
                <div><dt>Input</dt><dd>{selected.input}</dd></div>
                <div><dt>Grouped by</dt><dd>{selected.groupBy}</dd></div>
                <div><dt>Threshold</dt><dd>{selected.criteria}</dd></div>
                <div><dt>Loaded matches</dt><dd>{selected.activity.total}</dd></div>
                <div><dt>Latest match</dt><dd>{selected.activity.latest ? formatTimestamp(selected.activity.latest) : "No loaded match"}</dd></div>
              </dl>
              <div className="rule-logic-block">
                <span><Activity size={14} /> Detection logic</span>
                <code>{selected.query}</code>
              </div>
              <div className="rule-response-block">
                <span><Clock3 size={14} /> Recommended response</span>
                <p>{selected.response}</p>
              </div>
              <InlineNotice title={repositoryMode === "api" ? "Connected rule inventory" : "Sample rule inventory"} tone="info">
                {repositoryMode === "api"
                  ? "Alert activity is loaded from the API. Rule definitions mirror the current built-in backend implementation."
                  : "Sample alert activity is shown locally; the rule definitions still mirror the built-in backend implementation."}
              </InlineNotice>
            </div>
          ) : (
            <div className="detail-placeholder"><Search size={24} /><strong>No matching rule</strong><span>Clear the search to select a detection rule.</span></div>
          )}
        </Panel>
      </div>
    </>
  );
}
