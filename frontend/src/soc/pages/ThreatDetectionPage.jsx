import { useEffect, useMemo, useRef, useState } from "react";
import {
  Activity,
  Clock3,
  HeartPulse,
  Plus,
  RadioTower,
  RefreshCw,
  Search,
  ShieldCheck,
  Target,
  Trash2,
} from "lucide-react";
import {
  CURRENT_DETECTION_RULE_IDS,
  CURRENT_DETECTION_RULES,
  SAMPLE_DETECTION_RULE_IDS,
  SAMPLE_DETECTION_RULES,
  summarizeRuleActivity,
} from "../data/detectionRulePack";
import { getRuleCategory, RULE_CATEGORIES } from "../data/ruleCategories";
import {
  describeLiveConfig,
  draftFromLive,
  editableFields,
  ENTITY_LABELS,
  humanizeKey,
  updatesFromDraft,
} from "../utils/ruleConfig";
import { SOC_ROUTES } from "../../hooks/useAuthRoute";
import { useSocWorkspace } from "../context/SocWorkspaceContext";
import { socRepository } from "../services/socRepository";
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
import { ThreatIntelPanel } from "../components/ThreatIntelPanel";
import { HostHeartbeatPanel } from "../components/HostHeartbeatPanel";

const WINDOW_LABELS = Object.freeze({
  300: "5 minutes", 600: "10 minutes", 1800: "30 minutes", 3600: "1 hour", 86400: "24 hours",
});

function describeCustomConditions(rule) {
  const clauses = (rule.conditions || []).map((condition) => (
    `${condition.field} ${condition.operator} ${condition.value}`
  ));
  const windowLabel = WINDOW_LABELS[rule.windowSeconds] || `${rule.windowSeconds}s`;
  const groupLabel = rule.groupBy && rule.groupBy !== "none" ? `, grouped by ${rule.groupBy}` : "";
  return `${clauses.join(" AND ")}${groupLabel}, window ${windowLabel}`;
}

function customRuleToInventoryEntry(rule) {
  return {
    id: rule.id,
    backendId: rule.backendId,
    engineKey: "custom_condition_rule",
    category: rule.category,
    executable: true,
    isCustom: true,
    name: rule.name,
    description: "Custom rule authored in the Rule Builder.",
    technique: rule.tactic || "Not mapped",
    severity: rule.severity,
    status: rule.status,
    criteria: describeCustomConditions(rule),
    input: "Conditions over parsed log records (event_type, status, ip_address, username, port, timestamp)",
    groupBy: rule.groupBy === "none" ? "None" : rule.groupBy,
    query: rule.dsl || describeCustomConditions(rule),
    response: rule.actions?.suggest_playbook
      ? "Follow the linked response playbook and review the authored conditions if the rule is noisy."
      : "Review the authored conditions and adjust thresholds if the rule is noisy.",
  };
}

const ALL_CATEGORIES = Object.freeze([
  Object.freeze({ value: "all", label: "All", shortLabel: "All" }),
  ...RULE_CATEGORIES,
]);

const RULE_INVENTORY_IDS = Object.freeze([
  ...CURRENT_DETECTION_RULE_IDS,
  ...SAMPLE_DETECTION_RULE_IDS,
]);

const FALLBACK_RULES = Object.freeze({
  ...CURRENT_DETECTION_RULES,
  ...SAMPLE_DETECTION_RULES,
});

export default function ThreatDetectionPage({ navigate }) {
  const {
    alerts,
    canWrite,
    customRules,
    deleteCustomRule,
    detectionRules,
    repositoryMode,
    refresh,
    resources,
    updateCustomRuleStatus,
  } = useSocWorkspace();
  const [query, setQuery] = useState("");
  const [categoryFilter, setCategoryFilter] = useState("all");
  const [selectedId, setSelectedId] = useState(CURRENT_DETECTION_RULE_IDS[0]);
  const tabRefs = useRef([]);
  // detectionRules is a static import, never a fetched resource — the only
  // live resource behind this page's rule inventory is customRules.
  const ruleResource = resources.customRules || resources.alerts;

  const [builtInSettings, setBuiltInSettings] = useState({});
  const [builtInSettingsLoading, setBuiltInSettingsLoading] = useState(true);
  const [builtInSettingsError, setBuiltInSettingsError] = useState("");
  const [ruleConfigDraft, setRuleConfigDraft] = useState(null);
  const [ruleConfigSaving, setRuleConfigSaving] = useState(false);
  const [ruleConfigError, setRuleConfigError] = useState("");

  async function loadBuiltInSettings() {
    setBuiltInSettingsLoading(true);
    setBuiltInSettingsError("");
    try {
      const liveRules = await socRepository.getDetectionRules();
      setBuiltInSettings(Object.fromEntries(liveRules.map((rule) => [rule.engineKey, rule])));
    } catch (loadError) {
      setBuiltInSettingsError(loadError.message || "Detection rule configuration could not be loaded.");
    } finally {
      setBuiltInSettingsLoading(false);
    }
  }

  useEffect(() => {
    void loadBuiltInSettings();
    // Runs once on mount — the rule inventory is refreshed explicitly via
    // the page's own "Refresh activity" action and after a successful save.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const rules = useMemo(() => {
    const builtins = RULE_INVENTORY_IDS.map((ruleId) => {
      const fallback = FALLBACK_RULES[ruleId];
      const supplied = detectionRules?.[ruleId] || {};
      const rule = { ...fallback, ...supplied, id: ruleId };
      const live = rule.executable ? builtInSettings[rule.engineKey] : null;
      return {
        ...rule,
        live,
        status: live ? (live.enabled ? "enabled" : "disabled") : rule.status,
        categoryMeta: getRuleCategory(rule.category),
        activity: rule.executable ? summarizeRuleActivity(ruleId, alerts) : null,
      };
    });
    const custom = (customRules || []).map((rule) => {
      const entry = customRuleToInventoryEntry(rule);
      return {
        ...entry,
        categoryMeta: getRuleCategory(entry.category),
        activity: summarizeRuleActivity(entry.id, alerts),
      };
    });
    return [...builtins, ...custom];
  }, [alerts, customRules, detectionRules, builtInSettings]);

  async function updateBuiltInRule(engineKey, updates) {
    setRuleConfigSaving(true);
    setRuleConfigError("");
    try {
      const updated = await socRepository.updateDetectionRule(engineKey, updates);
      setBuiltInSettings((current) => ({ ...current, [engineKey]: updated }));
      setRuleConfigDraft(null);
      return updated;
    } catch (updateError) {
      setRuleConfigError(updateError.message || "That detection rule could not be updated.");
      return null;
    } finally {
      setRuleConfigSaving(false);
    }
  }

  const [ruleConfigFieldErrors, setRuleConfigFieldErrors] = useState({});

  function startRuleConfigEdit(rule) {
    if (!rule.live) return;
    setRuleConfigError("");
    setRuleConfigFieldErrors({});
    setRuleConfigDraft(draftFromLive(rule.live));
  }

  async function submitRuleConfigEdit(event) {
    event.preventDefault();
    if (!ruleConfigDraft) return;
    const rule = rules.find((item) => item.engineKey === ruleConfigDraft.engineKey);
    const { errors, updates } = updatesFromDraft(ruleConfigDraft, rule?.live);
    if (Object.keys(errors).length) {
      setRuleConfigFieldErrors(errors);
      return;
    }
    setRuleConfigFieldErrors({});
    if (!Object.keys(updates).length) {
      setRuleConfigDraft(null);
      return;
    }
    await updateBuiltInRule(ruleConfigDraft.engineKey, updates);
  }

  const categoryCounts = useMemo(() => Object.fromEntries([
    ["all", rules.length],
    ...RULE_CATEGORIES.map((category) => [
      category.value,
      rules.filter((rule) => rule.category === category.value).length,
    ]),
  ]), [rules]);

  const filtered = useMemo(() => {
    const term = query.trim().toLowerCase();
    return rules.filter((rule) => {
      if (categoryFilter !== "all" && rule.category !== categoryFilter) return false;
      if (!term) return true;
      return [
        rule.id,
        rule.engineKey,
        rule.name,
        rule.description,
        rule.technique,
        rule.criteria,
        rule.categoryMeta.label,
        rule.categoryMeta.description,
        rule.status,
      ].join(" ").toLowerCase().includes(term);
    });
  }, [categoryFilter, query, rules]);

  const selected = filtered.find((rule) => rule.id === selectedId) || filtered[0] || null;
  const executableRules = rules.filter((rule) => rule.executable);
  const sampleRules = rules.filter((rule) => !rule.executable);
  const totalMatches = executableRules.reduce((total, rule) => total + rule.activity.total, 0);
  const activeMatches = executableRules.reduce((total, rule) => total + rule.activity.active, 0);
  const triggeredRules = executableRules.filter((rule) => rule.activity.total > 0).length;
  const activeCategory = categoryFilter === "all"
    ? { label: "All categories", description: "Executable detectors and presentation-only examples across the complete rule inventory." }
    : getRuleCategory(categoryFilter);

  function handleTabKeyDown(event, index) {
    let nextIndex = null;
    if (event.key === "ArrowRight" || event.key === "ArrowDown") {
      nextIndex = (index + 1) % ALL_CATEGORIES.length;
    } else if (event.key === "ArrowLeft" || event.key === "ArrowUp") {
      nextIndex = (index - 1 + ALL_CATEGORIES.length) % ALL_CATEGORIES.length;
    } else if (event.key === "Home") {
      nextIndex = 0;
    } else if (event.key === "End") {
      nextIndex = ALL_CATEGORIES.length - 1;
    }
    if (nextIndex === null) return;
    event.preventDefault();
    setCategoryFilter(ALL_CATEGORIES[nextIndex].value);
    tabRefs.current[nextIndex]?.focus();
  }

  if ((resources.alerts.loading || ruleResource.loading) && !alerts.length) {
    return <LoadingState label="Loading detection rule activity…" />;
  }
  if ((resources.alerts.error || ruleResource.error) && !alerts.length) {
    return <ErrorState message={resources.alerts.error || ruleResource.error} onRetry={() => Promise.all([refresh("alerts"), refresh("customRules")])} />;
  }

  return (
    <>
      <PageHeader
        title="Threat Detection"
        description="Review executable detectors and category examples that fit the current SOC workflow."
        actions={(
          <>
            <button
              className="soc-button secondary"
              type="button"
              disabled={resources.alerts.loading || ruleResource.loading || builtInSettingsLoading}
              onClick={() => Promise.all([refresh("alerts"), refresh("customRules"), loadBuiltInSettings()])}
            >
              <RefreshCw size={15} className={resources.alerts.loading || ruleResource.loading || builtInSettingsLoading ? "spin" : ""} />
              Refresh activity
            </button>
            {canWrite && (
              <button
                className="soc-button primary"
                type="button"
                onClick={() => navigate?.(SOC_ROUTES.ruleBuilder)}
              >
                <Plus size={15} aria-hidden="true" />
                New custom rule
              </button>
            )}
          </>
        )}
      />

      <div className="soc-stats-grid">
        <StatCard label="Executable rules" value={String(executableRules.length)} trend="Built into DetectionEngine" tone="success" />
        <StatCard label="Category examples" value={String(sampleRules.length)} trend="Not executable" />
        <StatCard label="Rules triggered" value={String(triggeredRules)} trend={`${totalMatches} generated alert${totalMatches === 1 ? "" : "s"}`} />
        <StatCard label="Active matches" value={String(activeMatches)} trend="Not closed or resolved" tone={activeMatches ? "critical" : "success"} />
      </div>

      <InlineNotice className="rule-pack-notice" title="How the rule pack runs" tone="info">
        Accepted uploads are normalized into security events, all {executableRules.length} executable rules inspect the parsed batch, and matching alerts are saved with their evidence line numbers. Drafts, templates, and placeholders below are presentation-only and do not run in the detection engine.
      </InlineNotice>

      <section className="rule-category-browser" aria-labelledby="rule-category-heading">
        <div>
          <h2 id="rule-category-heading">Rule categories</h2>
          <p>{activeCategory.description}</p>
        </div>
        <div className="rule-category-tabs" role="tablist" aria-label="Filter rules by category">
          {ALL_CATEGORIES.map((category, index) => (
            <button
              id={`rule-category-tab-${category.value}`}
              aria-controls="rule-category-results"
              aria-selected={categoryFilter === category.value}
              className={categoryFilter === category.value ? "active" : ""}
              key={category.value}
              onClick={() => setCategoryFilter(category.value)}
              onKeyDown={(event) => handleTabKeyDown(event, index)}
              ref={(element) => { tabRefs.current[index] = element; }}
              role="tab"
              tabIndex={categoryFilter === category.value ? 0 : -1}
              type="button"
            >
              <span>{category.shortLabel}</span>
              <b>{categoryCounts[category.value] || 0}</b>
            </button>
          ))}
        </div>
      </section>

      <div
        aria-labelledby={`rule-category-tab-${categoryFilter}`}
        className="secondary-workspace detection-rule-workspace"
        id="rule-category-results"
        role="tabpanel"
      >
        <Panel title="Rule inventory" subtitle={`${filtered.length} of ${rules.length} definitions`}>
          <label className="secondary-search">
            <Search size={16} />
            <span className="sr-only">Search detection rules</span>
            <input
              type="search"
              maxLength="120"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search rule ID, category, technique, or behavior…"
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
                <span className="rule-list-meta">
                  <span className="rule-category-badge">{rule.categoryMeta.shortLabel}</span>
                  {rule.executable ? (
                    <span className="rule-match-count">{rule.activity.total} match{rule.activity.total === 1 ? "" : "es"}</span>
                  ) : (
                    <span className="rule-execution-label">{rule.status} · not executable</span>
                  )}
                </span>
              </button>
            ))}
            {!filtered.length && (
              <div className="table-empty">
                <Search size={22} />
                <strong>No detection rules match</strong>
                <span>Clear or adjust the search and category filter to restore the rule inventory.</span>
              </div>
            )}
          </div>
        </Panel>

        <Panel title="Rule details" subtitle={selected ? `${selected.id} · ${selected.engineKey || "no engine implementation"}` : "No rule selected"}>
          {selected ? (
            <div className="config-detail detection-rule-detail">
              <span className="config-detail-icon"><Target size={20} /></span>
              <div className="rule-detail-title">
                <div>
                  <span className="rule-category-badge">{selected.categoryMeta.label}</span>
                  <h3>{selected.name}</h3>
                  <p>{selected.description}</p>
                </div>
                <StatusBadge status={selected.status} />
              </div>
              <p className="rule-category-definition">{selected.categoryMeta.description}</p>
              <dl>
                <div><dt>Execution</dt><dd>{selected.executable ? "Executable detector" : `${selected.status} · presentation only`}</dd></div>
                <div><dt>Severity</dt><dd><SeverityBadge severity={selected.severity} /></dd></div>
                <div><dt>ATT&amp;CK</dt><dd>{selected.live?.mitreTechnique || selected.technique}</dd></div>
                {selected.live?.entityType && (
                  <div><dt>Pivots on</dt><dd>{ENTITY_LABELS[selected.live.entityType] || selected.live.entityType}</dd></div>
                )}
                <div><dt>Input</dt><dd>{selected.input}</dd></div>
                <div><dt>Grouped by</dt><dd>{selected.groupBy}</dd></div>
                {selected.logSource && <div><dt>Required log source</dt><dd>{selected.logSource}</dd></div>}
                <div><dt>Threshold</dt><dd>{selected.criteria}</dd></div>
                {selected.executable && !selected.isCustom && selected.live && (
                  <div>
                    <dt>Active configuration</dt>
                    <dd>{describeLiveConfig(selected.live)}</dd>
                  </div>
                )}
                {selected.executable && <div><dt>Loaded matches</dt><dd>{selected.activity.total}</dd></div>}
                {selected.executable && <div><dt>Latest match</dt><dd>{selected.activity.latest ? formatTimestamp(selected.activity.latest) : "No loaded match"}</dd></div>}
              </dl>
              {selected.setupNote && (
                <InlineNotice tone="warning" title="Setup required">{selected.setupNote}</InlineNotice>
              )}
              {selected.requiresAllowlist && selected.live && (selected.live.allowlist || []).length === 0 && (
                <InlineNotice tone="warning" title="Not configured">
                  This rule matches nothing until you add at least one entry to its allowlist below.
                </InlineNotice>
              )}
              <div className="rule-logic-block">
                <span><Activity size={14} /> {selected.executable ? "Detection logic" : "Example logic"}</span>
                <code>{selected.query}</code>
              </div>
              <div className="rule-response-block">
                <span><Clock3 size={14} /> Recommended response</span>
                <p>{selected.response}</p>
              </div>
              <InlineNotice title={selected.isCustom ? "Custom rule" : selected.executable ? (repositoryMode === "api" ? "Connected rule inventory" : "Sample rule activity") : "Presentation-only definition"} tone="info">
                {selected.isCustom
                  ? "Authored in the Rule Builder. It runs alongside the built-in rules on every future upload while enabled."
                  : selected.executable
                  ? (repositoryMode === "api"
                    ? "Alert activity is loaded from the API and this definition maps to a built-in backend detector."
                    : "Sample alert activity is shown locally; this definition still mirrors a built-in backend detector.")
                  : "This draft or template helps organize future work. It has no engine key and cannot inspect events or generate alerts."}
              </InlineNotice>
              {selected.executable && !selected.isCustom && canWrite && (
                <div className="rule-custom-actions built-in-rule-config">
                  {ruleConfigError && <InlineNotice tone="error" title="Update failed" onDismiss={() => setRuleConfigError("")}>{ruleConfigError}</InlineNotice>}
                  <div className="rule-custom-actions">
                    <button
                      className="soc-button secondary compact"
                      type="button"
                      disabled={!selected.live || ruleConfigSaving}
                      onClick={() => updateBuiltInRule(selected.engineKey, { enabled: !selected.live.enabled })}
                    >
                      {selected.live?.enabled === false ? "Enable rule" : "Disable rule"}
                    </button>
                    {selected.live && ruleConfigDraft?.engineKey !== selected.engineKey && (
                      <button
                        className="soc-button secondary compact"
                        type="button"
                        onClick={() => startRuleConfigEdit(selected)}
                      >
                        Edit thresholds
                      </button>
                    )}
                  </div>
                  {ruleConfigDraft?.engineKey === selected.engineKey && (
                    <form className="rule-threshold-form" onSubmit={submitRuleConfigEdit}>
                      {editableFields(selected.live).map((field) => (
                        <label key={field.key} className={field.kind === "list" ? "rule-threshold-form-wide" : ""}>
                          <span>{field.label}</span>
                          {field.kind === "list" ? (
                            <textarea
                              rows={3}
                              value={ruleConfigDraft.values[field.key] ?? ""}
                              placeholder="One name per line"
                              onChange={(event) => setRuleConfigDraft((current) => ({
                                ...current, values: { ...current.values, [field.key]: event.target.value },
                              }))}
                            />
                          ) : (
                            <input
                              type="number"
                              min={field.min}
                              max={field.max}
                              value={ruleConfigDraft.values[field.key] ?? ""}
                              onChange={(event) => setRuleConfigDraft((current) => ({
                                ...current, values: { ...current.values, [field.key]: event.target.value },
                              }))}
                            />
                          )}
                          {ruleConfigFieldErrors[field.key] && <small className="soc-field-error">{ruleConfigFieldErrors[field.key]}</small>}
                        </label>
                      ))}
                      {Object.entries(selected.live?.defaultParams || {}).map(([key]) => (
                        <label key={key}>
                          <span>{humanizeKey(key)}</span>
                          <input
                            type={typeof selected.live.defaultParams[key] === "number" ? "number" : "text"}
                            step="any"
                            value={ruleConfigDraft.params[key] ?? ""}
                            onChange={(event) => setRuleConfigDraft((current) => ({
                              ...current, params: { ...current.params, [key]: event.target.value },
                            }))}
                          />
                          {ruleConfigFieldErrors[`params.${key}`] && <small className="soc-field-error">{ruleConfigFieldErrors[`params.${key}`]}</small>}
                        </label>
                      ))}
                      <div className="rule-threshold-form-actions">
                        <button className="soc-button secondary compact" type="button" onClick={() => { setRuleConfigDraft(null); setRuleConfigFieldErrors({}); }} disabled={ruleConfigSaving}>Cancel</button>
                        <button className="soc-button primary compact" type="submit" disabled={ruleConfigSaving}>{ruleConfigSaving ? "Saving…" : "Save settings"}</button>
                      </div>
                    </form>
                  )}
                </div>
              )}
              {selected.isCustom && canWrite && (
                <div className="rule-custom-actions">
                  {selected.status !== "enabled" && (
                    <button
                      className="soc-button secondary compact"
                      type="button"
                      onClick={() => updateCustomRuleStatus(selected.backendId, "enabled")}
                    >
                      Enable rule
                    </button>
                  )}
                  {selected.status === "enabled" && (
                    <button
                      className="soc-button secondary compact"
                      type="button"
                      onClick={() => updateCustomRuleStatus(selected.backendId, "disabled")}
                    >
                      Disable rule
                    </button>
                  )}
                  <button
                    className="soc-button danger compact"
                    type="button"
                    onClick={() => deleteCustomRule(selected.backendId)}
                  >
                    <Trash2 size={14} aria-hidden="true" />
                    Delete rule
                  </button>
                </div>
              )}
            </div>
          ) : (
            <div className="detail-placeholder"><Search size={24} /><strong>No matching rule</strong><span>Clear the search or select another category to choose a detection rule.</span></div>
          )}
        </Panel>
      </div>

      <div className="secondary-workspace detection-rule-workspace">
        <ThreatIntelPanel canWrite={canWrite} icon={RadioTower} />
        <HostHeartbeatPanel canWrite={canWrite} icon={HeartPulse} />
      </div>
    </>
  );
}
