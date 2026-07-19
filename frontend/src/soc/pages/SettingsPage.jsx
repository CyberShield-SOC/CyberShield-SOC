import { useEffect, useMemo, useRef, useState } from "react";
import {
  BellRing,
  BookOpen,
  BrainCircuit,
  Building2,
  Database,
  ExternalLink,
  Palette,
  RotateCcw,
  Save,
  ShieldCheck,
} from "lucide-react";
import { useSocWorkspace } from "../context/SocWorkspaceContext";
import { SOC_ROUTES } from "../../hooks/useAuthRoute";
import { validateWorkspaceSettings } from "../utils/formValidation";
import { ErrorState, InlineNotice, LoadingState, PageHeader, Panel, ValidationMessage } from "../components/Ui";

const SECTIONS = [
  ["workspace", "Workspace", Building2],
  ["appearance", "Appearance", Palette],
  ["security", "Security", ShieldCheck],
  ["notifications", "Notifications", BellRing],
  ["data", "Data & privacy", Database],
  ["ai", "AI assistant", BrainCircuit],
  ["documentation", "Documentation", BookOpen],
];

function ToggleRow({ checked, description, disabled = false, label, onChange }) {
  return (
    <label className={`settings-toggle-row${disabled ? " disabled" : ""}`}>
      <span><strong>{label}</strong><small>{description}</small></span>
      <input type="checkbox" checked={checked} disabled={disabled} onChange={(event) => onChange(event.target.checked)} />
    </label>
  );
}

function CapabilityList({ items }) {
  return (
    <dl className="settings-capability-list">
      {items.map(([label, value, state = "ready"]) => (
        <div key={label}>
          <dt>{label}</dt>
          <dd data-state={state}><i aria-hidden="true" />{value}</dd>
        </div>
      ))}
    </dl>
  );
}

export default function SettingsPage({ navigate, theme, toggleTheme }) {
  const { canAdminister, repositoryMode, settings: data, resources, refresh, saveWorkspaceSettings } = useSocWorkspace();
  const error = resources.settings.error;
  const loading = resources.settings.loading;
  const [draft, setDraft] = useState(null);
  const [saved, setSaved] = useState(null);
  const [activeSection, setActiveSection] = useState("workspace");
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState("");
  const [savedMessage, setSavedMessage] = useState("");
  const [validationErrors, setValidationErrors] = useState({});
  const workspaceNameRef = useRef(null);

  useEffect(() => {
    if (!data) return;
    setDraft(structuredClone(data));
    setSaved(structuredClone(data));
  }, [data]);

  const dirty = useMemo(
    () => Boolean(draft && saved && JSON.stringify(draft) !== JSON.stringify(saved)),
    [draft, saved],
  );

  useEffect(() => {
    if (!dirty) return undefined;
    function warnBeforeLeaving(event) {
      event.preventDefault();
      event.returnValue = "";
    }
    window.addEventListener("beforeunload", warnBeforeLeaving);
    return () => window.removeEventListener("beforeunload", warnBeforeLeaving);
  }, [dirty]);

  function update(section, key, value) {
    setDraft((current) => ({
      ...current,
      [section]: { ...current[section], [key]: value },
    }));
    setSavedMessage("");
    setSaveError("");
    if (section === "workspace" && key === "name") {
      setValidationErrors((current) => ({ ...current, workspaceName: undefined }));
    }
  }

  function discardChanges() {
    setDraft(structuredClone(saved));
    setSavedMessage("");
    setSaveError("");
    setValidationErrors({});
  }

  async function save(event) {
    event.preventDefault();
    if (!dirty || saving) return;
    const nextErrors = validateWorkspaceSettings(draft);
    setValidationErrors(nextErrors);
    if (nextErrors.workspaceName) {
      workspaceNameRef.current?.focus();
      return;
    }

    const normalizedDraft = {
      ...draft,
      workspace: { ...draft.workspace, name: draft.workspace.name.trim() },
    };
    setSaving(true);
    setSaveError("");
    try {
      const next = await saveWorkspaceSettings(normalizedDraft);
      if (!next) throw new Error("Settings save failed");
      setDraft(structuredClone(next));
      setSaved(structuredClone(next));
      setSavedMessage("Workspace settings saved.");
    } catch {
      setSaveError("Settings could not be saved. Your draft is still available.");
    } finally {
      setSaving(false);
    }
  }

  if (error) return <ErrorState message={error} onRetry={() => refresh("settings")} />;
  if (loading || !draft) return <LoadingState label="Loading workspace settings…" />;

  return (
    <form onSubmit={save}>
      <PageHeader
        title="Settings"
        description="Configure working interface preferences and review the enforcement status of connected security services."
        actions={(
          <div className="settings-actions">
            <button className="soc-button secondary" type="button" disabled={!canAdminister || !dirty || saving} onClick={discardChanges}><RotateCcw size={15} />Discard</button>
            <button className="soc-button primary" type="submit" disabled={!canAdminister || !dirty || saving}>{saving ? <span className="soc-spinner small" /> : <Save size={15} />}{saving ? "Saving…" : "Save changes"}</button>
          </div>
        )}
      />

      <section className="settings-context-bar" aria-label="Workspace context">
        <span className="settings-context-icon" aria-hidden="true"><Building2 size={17} /></span>
        <span className="settings-context-copy"><small>Current workspace</small><strong>{draft.workspace.name}</strong></span>
        <span className="settings-context-state"><i aria-hidden="true" />{repositoryMode === "api" ? "Connected workspace" : "Local preview"}</span>
      </section>

      {(savedMessage || saveError) && (
        <InlineNotice className="settings-save-notice" tone={saveError ? "error" : "success"} title={saveError ? "Settings not saved" : "Settings updated"}>
          {saveError || savedMessage}
        </InlineNotice>
      )}
      {!canAdminister && <InlineNotice className="settings-save-notice" tone="info" title="Read-only settings">Only an Admin can change workspace settings.</InlineNotice>}

      <div className="settings-workspace">
        <nav className="settings-section-nav" aria-label="Settings sections">
          {SECTIONS.map(([id, label, Icon]) => (
            <button type="button" className={activeSection === id ? "active" : ""} key={id} onClick={() => setActiveSection(id)} aria-current={activeSection === id ? "page" : undefined}>
              <Icon size={17} /><span>{label}</span>
            </button>
          ))}
        </nav>

        <div className="settings-sections">
          {activeSection === "workspace" && (
            <Panel title="Workspace profile" subtitle={repositoryMode === "api" ? "These browser-session defaults are saved through the current interface settings adapter." : "Shared defaults for this local workspace preview."}>
              <div className="settings-form-grid">
                <label className={`span-2${validationErrors.workspaceName ? " has-error" : ""}`}>Workspace name<input ref={workspaceNameRef} value={draft.workspace.name} disabled={!canAdminister} maxLength="80" aria-invalid={Boolean(validationErrors.workspaceName)} aria-describedby={validationErrors.workspaceName ? "workspace-name-error" : undefined} onChange={(event) => update("workspace", "name", event.target.value)} /><ValidationMessage id="workspace-name-error">{validationErrors.workspaceName}</ValidationMessage></label>
                <label>Default time range<select value={draft.workspace.defaultTimeRange} disabled={!canAdminister} onChange={(event) => update("workspace", "defaultTimeRange", event.target.value)}><option value="1h">Last hour</option><option value="24h">Last 24 hours</option><option value="7d">Last 7 days</option><option value="30d">Last 30 days</option><option value="all">All available</option></select></label>
              </div>
            </Panel>
          )}

          {activeSection === "appearance" && (
            <Panel title="Appearance and accessibility" subtitle="Adjust how information is sized and arranged throughout the authenticated workspace.">
              <div className="settings-form-grid">
                <label>Color theme<select value={theme} onChange={(event) => event.target.value !== theme && toggleTheme()}><option value="dark">Dark</option><option value="light">Light</option></select></label>
                <label>Interface density<select value={draft.workspace.density} disabled={!canAdminister} onChange={(event) => update("workspace", "density", event.target.value)}><option value="compact">Compact</option><option value="comfortable">Comfortable</option><option value="spacious">Spacious</option></select></label>
                <label>Text size<select value={draft.workspace.textSize} disabled={!canAdminister} onChange={(event) => update("workspace", "textSize", event.target.value)}><option value="small">Small</option><option value="standard">Standard</option><option value="large">Large</option></select></label>
              </div>
              <div className="settings-toggle-list settings-appearance-toggles">
                <ToggleRow disabled={!canAdminister} label="Reduce motion" description="Minimize non-essential transitions and timeline animations." checked={draft.workspace.reduceMotion} onChange={(value) => update("workspace", "reduceMotion", value)} />
                <ToggleRow disabled={!canAdminister} label="Increase contrast" description="Strengthen borders and muted text for clearer separation." checked={draft.workspace.highContrast} onChange={(value) => update("workspace", "highContrast", value)} />
              </div>
              <p className="settings-footnote">Theme changes apply immediately. Other display preferences are applied after you save and never hide security evidence or controls.</p>
            </Panel>
          )}

          {activeSection === "security" && (
            <Panel title="Session and access policy" subtitle="Identity policy is enforced by the API, so this page reports status without creating unsafe browser-only controls.">
              <InlineNotice tone="info" title="Managed by the authentication service">Session lifetime, MFA requirements, and privileged reauthentication must be configured on the backend.</InlineNotice>
              <CapabilityList items={[
                ["Authenticated session", "Secure server-managed cookie"],
                ["Role enforcement", "Viewer, Analyst, and Admin"],
                ["MFA enrollment and enforcement", "Backend endpoint required", "pending"],
                ["Privileged-action reauthentication", "Backend policy required", "pending"],
              ]} />
            </Panel>
          )}

          {activeSection === "notifications" && (
            <Panel title="Notification routing" subtitle="Choose which live workspace events appear in the analyst notification center.">
              <div className="settings-toggle-list">
                <ToggleRow disabled={!canAdminister} label="Critical alerts" description="Notify when a new critical alert requires triage." checked={draft.notifications.criticalAlerts} onChange={(value) => update("notifications", "criticalAlerts", value)} />
                <ToggleRow disabled={!canAdminister} label="Incident escalations" description="Notify when an incident is escalated to management." checked={draft.notifications.incidentEscalations} onChange={(value) => update("notifications", "incidentEscalations", value)} />
              </div>
              <p className="settings-footnote">Email, messaging, scheduled digests, and audio require a notification worker and delivery integrations before they can be enabled safely.</p>
            </Panel>
          )}

          {activeSection === "data" && (
            <Panel title="Data and privacy" subtitle="Current ingestion and persistence capabilities reported by this application build.">
              <CapabilityList items={[
                ["Accepted event files", ".log, .csv, .json, and .jsonl"],
                ["Maximum upload", "10 MB per file"],
                ["Event and case storage", repositoryMode === "api" ? "Persistent database" : "Local demo dataset"],
                ["Retention lifecycle", "Backend policy required", "pending"],
                ["Field-level masking", "Backend policy required", "pending"],
              ]} />
              <p className="settings-footnote">Retention and masking are intentionally unavailable until the API can enforce them consistently across views, searches, and exports.</p>
            </Panel>
          )}

          {activeSection === "ai" && (
            <Panel title="AI assistant boundaries" subtitle="Configure analyst-assist behavior without granting autonomous response authority.">
              <div className="settings-toggle-list">
                <ToggleRow disabled={!canAdminister} label="Enable AI assistant" description="Allow analysts to query evidence through the AI workspace." checked={draft.ai.enabled} onChange={(value) => update("ai", "enabled", value)} />
              </div>
              <CapabilityList items={[
                ["Human review", "Required for every state-changing action"],
                ["Evidence provenance", "Always displayed"],
                ["Conversation persistence", "Not retained by the backend", "pending"],
              ]} />
            </Panel>
          )}

          {activeSection === "documentation" && (
            <Panel title="Documentation" subtitle="Open task guidance, role information, and operational reference material.">
              <div className="settings-documentation-grid">
                {[
                  ["SOC quick start", "Follow the login, ingestion, alert-triage, and incident workflow."],
                  ["Investigation guide", "Learn how alerts, evidence, detection rules, incidents, and notes connect."],
                  ["Roles and permissions", "Review the Viewer, Analyst, and Admin access boundaries."],
                  ["Keyboard and accessibility", "See search shortcuts, focus behavior, and display preferences."],
                ].map(([title, description]) => (
                  <button type="button" key={title} onClick={() => navigate(SOC_ROUTES.help)}>
                    <span><BookOpen size={17} /><strong>{title}</strong></span>
                    <small>{description}</small>
                    <em>Open in Help center <ExternalLink size={13} /></em>
                  </button>
                ))}
              </div>
              <p className="settings-footnote">The Help center documents the behavior available in this build. Backend contracts and deployment notes remain in the repository documentation.</p>
            </Panel>
          )}
        </div>
      </div>
    </form>
  );
}
