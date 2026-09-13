import { useId, useMemo, useRef, useState } from "react";
import {
  AlertTriangle,
  ArrowLeft,
  Check,
  CircleAlert,
  CircleCheck,
  Play,
  Plus,
  X,
} from "lucide-react";
import { SOC_ROUTES } from "../../hooks/useAuthRoute";
import { useSocWorkspace } from "../context/SocWorkspaceContext";
import { InlineNotice, Panel } from "../components/Ui";
import {
  ACTION_OPTIONS,
  FIELD_CATALOG,
  GROUP_OPTIONS,
  INITIAL_CONDITIONS,
  MITRE_TACTIC_OPTIONS,
  OPERATORS_BY_TYPE,
  OVERLAP_WARNING,
  RULE_BUILDER_DEFAULTS,
  SEVERITY_OPTIONS,
  WINDOW_OPTIONS,
  WINDOW_SECONDS_BY_VALUE,
} from "../data/ruleBuilderMockData";
import "./RuleBuilderPage.css";
import { RULE_CATEGORIES } from "../data/ruleCategories";

const FIELD_TYPES = Object.fromEntries(FIELD_CATALOG.map((field) => [field.value, field.type]));
const VALID_SEVERITIES = new Set(SEVERITY_OPTIONS.map((option) => option.value));

function fieldTypeOf(field) {
  return FIELD_TYPES[field] || "string";
}

function operatorsFor(field) {
  return OPERATORS_BY_TYPE[fieldTypeOf(field)] || OPERATORS_BY_TYPE.string;
}

/** "00:00 – 06:00" (also accepts "-"/"–" with loose spacing) -> { from: "00", to: "06" } */
function parseHourRange(value) {
  const match = String(value || "").match(/^\s*(\d{1,2}):\d{2}\s*[–-]\s*(\d{1,2}):\d{2}\s*$/);
  if (!match) return null;
  return { from: match[1].padStart(2, "0"), to: match[2].padStart(2, "0") };
}

/**
 * Turns one condition into DSL fragments: [{ text, kind }].
 * Kinds map to syntax-highlight classes: field, op, value, fn, punct.
 */
function conditionToDsl(condition) {
  const type = fieldTypeOf(condition.field);
  const value = String(condition.value || "").trim();
  const field = { text: condition.field, kind: "field" };

  if (type === "number") {
    const compact = { text: value.replace(/\s+/g, ""), kind: "value" };
    if (condition.operator === "sum >" || condition.operator === "avg >") {
      const fn = condition.operator === "sum >" ? "sum" : "avg";
      return [
        { text: `${fn}(`, kind: "fn" }, field, { text: ")", kind: "fn" },
        { text: " > ", kind: "op" }, compact,
      ];
    }
    return [field, { text: ` ${condition.operator} `, kind: "op" }, compact];
  }

  if (type === "timestamp") {
    if (condition.operator === "between") {
      const range = parseHourRange(value);
      if (range) {
        return [
          { text: "hour(", kind: "fn" }, { text: "ts", kind: "field" }, { text: ")", kind: "fn" },
          { text: " in ", kind: "op" }, { text: `${range.from}..${range.to}`, kind: "value" },
        ];
      }
      return [
        { text: "ts", kind: "field" }, { text: " between ", kind: "op" },
        { text: `"${value}"`, kind: "value" },
      ];
    }
    const symbol = condition.operator === "before" ? "<" : ">";
    return [{ text: "ts", kind: "field" }, { text: ` ${symbol} `, kind: "op" }, { text: `"${value}"`, kind: "value" }];
  }

  if (condition.operator === "contains") {
    return [
      { text: "contains(", kind: "fn" }, field, { text: ", ", kind: "punct" },
      { text: `"${value}"`, kind: "value" }, { text: ")", kind: "fn" },
    ];
  }
  if (condition.operator === "in") {
    const items = value.split(",").map((item) => `"${item.trim()}"`).join(", ");
    return [field, { text: " in ", kind: "op" }, { text: `(${items})`, kind: "value" }];
  }
  const symbol = condition.operator === "not equals" ? "!=" : "==";
  return [field, { text: ` ${symbol} `, kind: "op" }, { text: `"${value}"`, kind: "value" }];
}

function validateDraft({ conditions, groupBy, ruleName, severity, window: windowValue, category }) {
  const problems = [];
  if (!ruleName.trim()) problems.push("Rule name is required");
  if (!category) problems.push("Category is required");
  if (!VALID_SEVERITIES.has(severity)) problems.push("Severity is not a supported level");
  conditions.forEach((condition, index) => {
    const position = index + 1;
    if (!FIELD_TYPES[condition.field]) return; // reported by the schema check
    if (!operatorsFor(condition.field).includes(condition.operator)) {
      problems.push(`Condition ${position} operator is not valid for ${condition.field}`);
    }
    if (!String(condition.value || "").trim()) {
      problems.push(`Condition ${position} is missing a value`);
    }
  });
  if (!groupBy) problems.push("Group by is required");
  if (!windowValue) problems.push("Window is required");

  const unknownFields = conditions
    .filter((condition) => !FIELD_TYPES[condition.field])
    .map((condition) => condition.field || "(empty)");

  return { syntaxProblems: problems, unknownFields };
}

export default function RuleBuilderPage({ navigate }) {
  const baseId = useId();
  const conditionKeyRef = useRef(0);
  const { canWrite, createCustomRule, nextCustomRuleId, testCustomRule } = useSocWorkspace();
  const [ruleName, setRuleName] = useState(RULE_BUILDER_DEFAULTS.name);
  const [category, setCategory] = useState(RULE_BUILDER_DEFAULTS.category);
  const [severity, setSeverity] = useState(RULE_BUILDER_DEFAULTS.severity);
  const [tactic, setTactic] = useState(RULE_BUILDER_DEFAULTS.tactic);
  const [conditions, setConditions] = useState(() => INITIAL_CONDITIONS.map((condition) => ({
    ...condition,
    key: `c${(conditionKeyRef.current += 1)}`,
  })));
  const [groupBy, setGroupBy] = useState(RULE_BUILDER_DEFAULTS.groupBy);
  const [windowValue, setWindowValue] = useState(RULE_BUILDER_DEFAULTS.window);
  const [actions, setActions] = useState(() => Object.fromEntries(
    ACTION_OPTIONS.map((action) => [action.id, action.checked]),
  ));
  const [testState, setTestState] = useState("idle");
  const [testResult, setTestResult] = useState(null);
  const [testError, setTestError] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [saveError, setSaveError] = useState("");
  const [savingAction, setSavingAction] = useState(null); // "draft" | "enable" | null
  const [savedRule, setSavedRule] = useState(null);

  const ruleIdLabel = savedRule
    ? `${savedRule.id} · saved`
    : `${nextCustomRuleId || RULE_BUILDER_DEFAULTS.ruleId} · auto-assigned`;

  const validation = useMemo(
    () => validateDraft({ conditions, groupBy, ruleName, severity, window: windowValue, category }),
    [conditions, groupBy, ruleName, severity, windowValue, category],
  );
  const syntaxValid = !validation.syntaxProblems.length;
  const schemaValid = !validation.unknownFields.length;
  const hasEmptyConditionValue = conditions.some((condition) => !String(condition.value || "").trim());

  const dslLines = useMemo(() => {
    const lines = [[
      { text: "rule ", kind: "keyword" },
      { text: savedRule?.id || nextCustomRuleId || RULE_BUILDER_DEFAULTS.ruleId, kind: "field" },
      { text: ` "${ruleName.trim()}" `, kind: "value" },
      { text: "{", kind: "punct" },
    ]];
    lines.push([{ text: "  category: ", kind: "keyword" }, { text: category, kind: "field" }]);
    conditions.forEach((condition, index) => {
      lines.push([
        { text: index === 0 ? "  when " : "   and ", kind: "keyword" },
        ...conditionToDsl(condition),
      ]);
    });
    lines.push([{ text: "  group by ", kind: "keyword" }, { text: groupBy, kind: "field" }]);
    lines.push([{ text: "  window ", kind: "keyword" }, { text: windowValue, kind: "value" }]);
    lines.push([
      { text: "  then ", kind: "keyword" },
      { text: "alert(", kind: "fn" },
      { text: "severity: ", kind: "punct" },
      { text: severity.toUpperCase(), kind: "value" },
      { text: ")", kind: "fn" },
    ]);
    lines.push([{ text: "}", kind: "punct" }]);
    return lines;
  }, [conditions, groupBy, nextCustomRuleId, ruleName, savedRule, severity, windowValue, category]);

  const dslText = useMemo(
    () => dslLines.map((line) => line.map((fragment) => fragment.text).join("")).join("\n"),
    [dslLines],
  );

  function updateCondition(key, patch) {
    setConditions((current) => current.map((condition) => (
      condition.key === key ? { ...condition, ...patch } : condition
    )));
    setConfirmation("");
  }

  function changeConditionField(key, field) {
    // The old value's format (e.g. "00:00 – 06:00") is almost never valid
    // for the new field's type, so clear it rather than leave a stale value
    // that would silently never match once the rule runs.
    updateCondition(key, { field, operator: operatorsFor(field)[0], value: "" });
  }

  function addCondition() {
    setConditions((current) => [...current, {
      key: `c${(conditionKeyRef.current += 1)}`,
      field: FIELD_CATALOG[0].value,
      operator: operatorsFor(FIELD_CATALOG[0].value)[0],
      value: "",
    }]);
    setConfirmation("");
  }

  function removeCondition(key) {
    setConditions((current) => (current.length > 1
      ? current.filter((condition) => condition.key !== key)
      : current));
    setConfirmation("");
  }

  function buildPayload(status) {
    return {
      name: ruleName.trim() || "Untitled rule",
      category,
      severity,
      tactic,
      conditions: conditions.map(({ field, operator, value }) => ({ field, operator, value })),
      groupBy,
      windowSeconds: WINDOW_SECONDS_BY_VALUE[windowValue] || 600,
      actions,
      status,
      dsl: dslText,
    };
  }

  async function runTest() {
    if (testState === "loading") return;
    setTestState("loading");
    setTestError("");
    try {
      const result = await testCustomRule(buildPayload());
      setTestResult(result);
      setTestState("done");
    } catch (error) {
      setTestError(error.message || "The rule could not be tested against sample logs.");
      setTestState("idle");
    }
  }

  async function saveRule(status) {
    if (savingAction) return;
    setSavingAction(status);
    setSaveError("");
    try {
      const created = await createCustomRule(buildPayload(status));
      if (!created) {
        setSaveError("The custom rule could not be saved. Check the form and try again.");
        return;
      }
      setSavedRule(created);
      setConfirmation(status === "enabled"
        ? `Rule ${created.id} "${ruleName.trim() || "Untitled rule"}" is enabled. It now runs alongside R-101…R-106 on every future upload.`
        : `Draft saved. ${created.id} "${ruleName.trim() || "Untitled rule"}" is kept in the custom rule library.`);
    } catch (error) {
      setSaveError(error.message || "The custom rule could not be saved.");
    } finally {
      setSavingAction(null);
    }
  }

  const showResult = testState !== "loading" && testResult;

  return (
    <>
      <header className="soc-page-header rule-builder-header">
        <div>
          <button className="soc-text-button rule-builder-back" type="button" onClick={() => navigate(SOC_ROUTES.threatDetection)}>
            <ArrowLeft size={14} aria-hidden="true" />
            Back to rules
          </button>
          <h1>New custom rule</h1>
          <p>Added to the custom rule library · runs alongside R-101…R-106</p>
        </div>
        <div className="soc-page-actions">
          <button
            className="soc-button secondary"
            type="button"
            disabled={!canWrite || Boolean(savedRule) || Boolean(savingAction) || hasEmptyConditionValue}
            title={savedRule
              ? `${savedRule.id} is already saved — go back to author another rule`
              : hasEmptyConditionValue
              ? "Every condition needs a value before the draft can be saved"
              : undefined}
            onClick={() => saveRule("draft")}
          >
            {savingAction === "draft" ? <span className="soc-spinner small" aria-hidden="true" /> : null}
            Save draft
          </button>
          <button
            className="soc-button primary"
            type="button"
            disabled={!canWrite || Boolean(savedRule) || Boolean(savingAction) || hasEmptyConditionValue || !syntaxValid || !schemaValid}
            title={savedRule
              ? `${savedRule.id} is already saved — go back to author another rule`
              : hasEmptyConditionValue
              ? "Every condition needs a value before the rule can be enabled"
              : (!syntaxValid || !schemaValid) ? "Resolve the validation issues before enabling this rule" : undefined}
            onClick={() => saveRule("enabled")}
          >
            {savingAction === "enabled" ? <span className="soc-spinner small" aria-hidden="true" /> : <Check size={15} aria-hidden="true" />}
            Enable rule
          </button>
        </div>
      </header>

      {saveError && (
        <InlineNotice className="rule-builder-confirmation" tone="error" title="Could not save rule" onDismiss={() => setSaveError("")}>
          {saveError}
        </InlineNotice>
      )}

      {confirmation && (
        <InlineNotice className="rule-builder-confirmation" tone="success" title="Saved" onDismiss={() => setConfirmation("")}>
          {confirmation}
        </InlineNotice>
      )}

      <div className="rule-builder-workspace">
        <div className="rule-builder-editor">
          <Panel title="Rule definition">
            <div className="rule-builder-definition-grid">
              <label className="rule-builder-field span-2" htmlFor={`${baseId}-name`}>
                <span>Rule name</span>
                <input
                  id={`${baseId}-name`}
                  type="text"
                  maxLength="120"
                  value={ruleName}
                  onChange={(event) => { setRuleName(event.target.value); setConfirmation(""); }}
                />
              </label>
              <label className="rule-builder-field" htmlFor={`${baseId}-rule-id`}>
                <span>Rule ID</span>
                <input
                  id={`${baseId}-rule-id`}
                  className="rule-builder-mono"
                  type="text"
                  value={ruleIdLabel}
                  disabled
                />
              </label>
              <label className="rule-builder-field" htmlFor={`${baseId}-category`}>
                <span>Category</span>
                <select id={`${baseId}-category`} value={category} onChange={(event) => { setCategory(event.target.value); setConfirmation(""); }}>
                  {RULE_CATEGORIES.map((option) => (
                    <option key={option.value} value={option.value}>{option.label}</option>
                  ))}
                </select>
              </label>
              <label className="rule-builder-field" htmlFor={`${baseId}-tactic`}>
                <span>MITRE ATT&amp;CK tactic</span>
                <select id={`${baseId}-tactic`} value={tactic} onChange={(event) => { setTactic(event.target.value); setConfirmation(""); }}>
                  {MITRE_TACTIC_OPTIONS.map((option) => (
                    <option key={option.value} value={option.value}>{option.label}</option>
                  ))}
                </select>
              </label>
            </div>
            <fieldset className="rule-builder-severity">
              <legend>Severity</legend>
              <div className="rule-builder-severity-group" role="presentation">
                {SEVERITY_OPTIONS.map((option) => (
                  <label
                    key={option.value}
                    className={severity === option.value ? "selected" : ""}
                    data-severity={option.value}
                  >
                    <input
                      type="radio"
                      name={`${baseId}-severity`}
                      value={option.value}
                      checked={severity === option.value}
                      onChange={() => { setSeverity(option.value); setConfirmation(""); }}
                    />
                    <i aria-hidden="true" />
                    {option.label}
                  </label>
                ))}
              </div>
            </fieldset>
          </Panel>

          <Panel
            title="Conditions — WHEN"
            subtitle="all conditions must match"
            actions={(
              <button className="soc-button secondary compact" type="button" onClick={addCondition}>
                <Plus size={14} aria-hidden="true" />
                Add condition
              </button>
            )}
          >
            <div className="rule-builder-conditions">
              {conditions.map((condition, index) => {
                const rowId = `${baseId}-${condition.key}`;
                const isFirst = index === 0;
                return (
                  <div className="rule-builder-condition-row" key={condition.key}>
                    <span className="rule-builder-chip" data-chip={isFirst ? "where" : "and"}>
                      {isFirst ? "WHERE" : "AND"}
                    </span>
                    <label className="sr-only" htmlFor={`${rowId}-field`}>Condition {index + 1} field</label>
                    <select
                      id={`${rowId}-field`}
                      className="rule-builder-mono"
                      value={condition.field}
                      onChange={(event) => changeConditionField(condition.key, event.target.value)}
                    >
                      {FIELD_CATALOG.map((field) => (
                        <option key={field.value} value={field.value}>{field.value}</option>
                      ))}
                    </select>
                    <label className="sr-only" htmlFor={`${rowId}-operator`}>Condition {index + 1} operator</label>
                    <select
                      id={`${rowId}-operator`}
                      className="rule-builder-mono"
                      value={condition.operator}
                      onChange={(event) => updateCondition(condition.key, { operator: event.target.value })}
                    >
                      {operatorsFor(condition.field).map((operator) => (
                        <option key={operator} value={operator}>{operator}</option>
                      ))}
                    </select>
                    <label className="sr-only" htmlFor={`${rowId}-value`}>Condition {index + 1} value</label>
                    <input
                      id={`${rowId}-value`}
                      className="rule-builder-mono"
                      type="text"
                      maxLength="120"
                      value={condition.value}
                      aria-invalid={String(condition.value || "").trim() ? undefined : "true"}
                      placeholder="value"
                      onChange={(event) => updateCondition(condition.key, { value: event.target.value })}
                    />
                    <button
                      className="rule-builder-remove"
                      type="button"
                      disabled={isFirst}
                      aria-label={isFirst
                        ? "The first condition cannot be removed"
                        : `Remove condition ${index + 1}`}
                      title={isFirst ? "The first condition cannot be removed" : `Remove condition ${index + 1}`}
                      onClick={() => removeCondition(condition.key)}
                    >
                      <X size={14} aria-hidden="true" />
                    </button>
                  </div>
                );
              })}
            </div>
            <div className="rule-builder-scope-row">
              <label htmlFor={`${baseId}-group`}>
                <span>GROUP</span>
                <select id={`${baseId}-group`} className="rule-builder-mono" value={groupBy} onChange={(event) => { setGroupBy(event.target.value); setConfirmation(""); }}>
                  {GROUP_OPTIONS.map((option) => (
                    <option key={option.value} value={option.value}>{option.label}</option>
                  ))}
                </select>
              </label>
              <label htmlFor={`${baseId}-window`}>
                <span>WINDOW</span>
                <select id={`${baseId}-window`} className="rule-builder-mono" value={windowValue} onChange={(event) => { setWindowValue(event.target.value); setConfirmation(""); }}>
                  {WINDOW_OPTIONS.map((option) => (
                    <option key={option.value} value={option.value}>{option.label}</option>
                  ))}
                </select>
              </label>
            </div>
          </Panel>

          <Panel title="Actions — THEN">
            <div className="rule-builder-actions-list">
              {ACTION_OPTIONS.map((action) => (
                <label
                  key={action.id}
                  className={`rule-builder-action${action.muted && !actions[action.id] ? " muted" : ""}`}
                  htmlFor={`${baseId}-${action.id}`}
                >
                  <input
                    id={`${baseId}-${action.id}`}
                    type="checkbox"
                    checked={actions[action.id]}
                    onChange={(event) => {
                      const next = event.target.checked;
                      setActions((current) => ({ ...current, [action.id]: next }));
                      setConfirmation("");
                    }}
                  />
                  <span>{action.label}</span>
                </label>
              ))}
            </div>
          </Panel>
        </div>

        <div className="rule-builder-rail">
          <Panel title="Test against sample logs" actions={<span className="rule-builder-panel-meta">most recent logs</span>}>
            <button
              className="soc-button primary full rule-builder-run-test"
              type="button"
              disabled={testState === "loading"}
              onClick={runTest}
            >
              {testState === "loading"
                ? <><span className="soc-spinner small" aria-hidden="true" />Running…</>
                : <><Play size={15} aria-hidden="true" />Run test</>}
            </button>
            <div className="rule-builder-test-shell" role="status" aria-live="polite">
              {testState === "loading" && (
                <div className="rule-builder-test-loading">
                  <span className="soc-spinner" aria-hidden="true" />
                  <span>Testing rule against sampled events…</span>
                </div>
              )}
              {testState !== "loading" && testError && (
                <InlineNotice tone="error" title="Test failed">{testError}</InlineNotice>
              )}
              {testState !== "loading" && !testError && showResult && (
                <>
                  <div className="rule-builder-test-summary">
                    <i className="rule-builder-ok-dot" aria-hidden="true" />
                    <span className="rule-builder-match-badge">{testResult.matchCount} MATCHES</span>
                    <span>in {testResult.sampledCount.toLocaleString()} sampled events</span>
                  </div>
                  <ul className="rule-builder-match-list">
                    {testResult.matches.length === 0 && <li>No matching events in the sampled logs.</li>}
                    {testResult.matches.map((match, index) => (
                      <li key={`${match.timestamp}-${index}`}>
                        {match.timestamp ? new Date(match.timestamp).toLocaleString() : "unknown time"}
                        {" "}{match.ipAddress || "—"} {match.eventType || "—"}
                        {match.username ? ` (${match.username})` : ""}
                        {match.port ? ` :${match.port}` : ""}
                      </li>
                    ))}
                  </ul>
                  <div className="rule-builder-noise">
                    <strong>Estimated noise: {testResult.noise.label}</strong>
                    <span>~{testResult.noise.alertsPerDay} alerts/day at current traffic{testResult.noise.label === "LOW" ? ". Safe to enable." : "."}</span>
                  </div>
                </>
              )}
              {testState !== "loading" && !testError && !showResult && (
                <div className="rule-builder-test-loading">
                  <span>Run the test to see how this rule performs against recent logs.</span>
                </div>
              )}
            </div>
          </Panel>

          <Panel title="Rule preview" actions={<span className="rule-builder-panel-meta">generated DSL</span>}>
            <pre className="rule-builder-dsl" aria-label="Generated rule DSL">
              <code>
                {dslLines.map((fragments, lineIndex) => (
                  <span className="rule-builder-dsl-line" key={lineIndex}>
                    {fragments.map((fragment, fragmentIndex) => (
                      <span key={fragmentIndex} data-dsl={fragment.kind}>{fragment.text}</span>
                    ))}
                  </span>
                ))}
              </code>
            </pre>
          </Panel>

          <Panel title="Validation">
            <ul className="rule-builder-validation">
              <li data-state={syntaxValid ? "ok" : "error"}>
                {syntaxValid
                  ? <><CircleCheck size={14} aria-hidden="true" /><span>Syntax valid</span></>
                  : <><CircleAlert size={14} aria-hidden="true" /><span>Syntax invalid — {validation.syntaxProblems[0]}</span></>}
              </li>
              <li data-state={schemaValid ? "ok" : "error"}>
                {schemaValid
                  ? <><CircleCheck size={14} aria-hidden="true" /><span>All fields exist in event schema</span></>
                  : <><CircleAlert size={14} aria-hidden="true" /><span>Unknown field: {validation.unknownFields.join(", ")}</span></>}
              </li>
              <li data-state="warning">
                <AlertTriangle size={14} aria-hidden="true" />
                <span>{OVERLAP_WARNING}</span>
              </li>
            </ul>
          </Panel>
        </div>
      </div>
    </>
  );
}
