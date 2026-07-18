import { useEffect, useMemo, useRef, useState } from "react";
import {
  AlertTriangle,
  Bot,
  CalendarDays,
  Database,
  KeyRound,
  ListChecks,
  MessageSquareText,
  Network,
  Send,
  ShieldCheck,
  Sparkles,
  UserRound,
  Users,
} from "lucide-react";
import { SOC_ROUTES } from "../../hooks/useAuthRoute";
import { useSocWorkspace } from "../context/SocWorkspaceContext";
import { socRepository } from "../services/socRepository";
import { formatTimestamp } from "../utils/eventUtils";
import { nextIncidentId } from "../utils/recordIds";
import { isTerminalIncidentStatus } from "../utils/incidentWorkflow";
import { InlineNotice, PageHeader, Panel, RiskMeter, SeverityBadge } from "../components/Ui";

const STARTER_MESSAGE = Object.freeze({
  id: "assistant-welcome",
  role: "assistant",
  body: "Hello! I’m your CyberShield AI assistant. Ask about alerts, incidents, authentication activity, or the evidence currently loaded in this workspace.",
});

const SUGGESTED_PROMPTS = [
  "Show unusual activity in the last 24 hours",
  "What are the top attack sources?",
  "Summarize this week’s security events",
  "Show users with multiple failed logins",
];

export default function AiAnalysisPage({ navigate }) {
  const {
    activeAlertCount,
    addNote,
    alerts,
    canAdminister,
    canWrite,
    currentActor,
    createIncident,
    events,
    incidents,
    mutation,
    repositoryMode,
    selectedIncidentId,
    setSelectedIncidentId,
    settings,
  } = useSocWorkspace();
  const [messages, setMessages] = useState([STARTER_MESSAGE]);
  const [prompt, setPrompt] = useState("");
  const [running, setRunning] = useState(false);
  const [error, setError] = useState("");
  const [lastAnalysis, setLastAnalysis] = useState(null);
  const messageListRef = useRef(null);
  const questionCount = messages.filter((message) => message.role === "user").length;
  const aiEnabled = settings?.ai?.enabled !== false;
  const availableSourceAlert = alerts.find((alert) => (
    alert.sourceAlertId
    && !incidents.some((incident) => incident.sourceAlertId === alert.sourceAlertId)
  ));

  useEffect(() => {
    const list = messageListRef.current;
    if (list) list.scrollTop = list.scrollHeight;
  }, [messages, running]);

  const failedEvidence = useMemo(
    () => events.filter((event) => event.status === "failed").sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp)).slice(0, 5),
    [events],
  );

  const recommendations = [
    { icon: ShieldCheck, title: "Enable multi-factor authentication", detail: "Review the workspace MFA policy and administrative reauthentication controls.", label: "View settings", route: SOC_ROUTES.settings },
    { icon: AlertTriangle, title: "Review critical alerts", detail: `${alerts.filter((alert) => alert.severity === "critical" && !["resolved", "contained"].includes(alert.status)).length} critical alerts currently require analyst review.`, label: "View alerts", route: SOC_ROUTES.alerts },
    { icon: Network, title: "Review firewall integration", detail: "Validate telemetry health before applying perimeter block recommendations.", label: "View integration", route: SOC_ROUTES.integrations },
    { icon: Users, title: "Complete user access review", detail: "Confirm analyst and administrator roles follow least-privilege policy.", label: canAdminister ? "Review users" : "Review permissions", route: canAdminister ? SOC_ROUTES.users : SOC_ROUTES.help },
  ];

  async function askQuestion(question) {
    const value = String(question || "").trim();
    if (!value || running || !aiEnabled) return;

    const userMessage = { id: `user-${Date.now()}`, role: "user", body: value };
    setMessages((current) => [...current, userMessage]);
    setPrompt("");
    setRunning(true);
    setError("");

    try {
      const analysis = await socRepository.runAiAnalysis({ subject: value });
      setLastAnalysis(analysis);
      setMessages((current) => [...current, {
        id: `assistant-${Date.now()}`,
        role: "assistant",
        body: analysis.summary,
        analysis,
      }]);
    } catch {
      setError("The analysis service is unavailable. Your question was not lost; try again when the service reconnects.");
    } finally {
      setRunning(false);
    }
  }

  function submitQuestion(event) {
    event.preventDefault();
    askQuestion(prompt);
  }

  async function copyToNotes(analysis = lastAnalysis) {
    if (!analysis || mutation.loading) return;
    if (repositoryMode === "api" && !incidents.length) {
      setError("Create an incident before saving connected AI analysis as an analyst note.");
      return;
    }
    // Prefer the analyst's current case instead of silently attaching AI
    // output to whichever incident happened to be returned first.
    const linkedIncident = incidents.find((incident) => incident.id === selectedIncidentId)
      || incidents.find((incident) => !isTerminalIncidentStatus(incident.status))
      || incidents[0];
    await addNote({
      title: `AI assessment · ${analysis.subject}`,
      body: `${analysis.summary}\n\nEvidence\n- ${analysis.evidence.join("\n- ")}\n\nRecommended actions\n- ${analysis.actions.join("\n- ")}`,
      tags: ["ai-assist", "analyst-review"],
      linkedType: repositoryMode === "api" ? "incident" : analysis.subject.startsWith("EVT-") ? "event" : "workspace",
      linkedId: repositoryMode === "api" ? linkedIncident.id : analysis.subject,
    });
  }

  async function createDraftIncident(analysis = lastAnalysis) {
    if (!analysis || mutation.loading) return;
    if (repositoryMode === "api" && !availableSourceAlert) {
      setError("Every persisted alert is already linked, so a new incident cannot be created from this analysis.");
      return;
    }
    const sourceAlert = repositoryMode === "api" ? availableSourceAlert : null;
    const created = await createIncident({
      id: nextIncidentId(incidents),
      title: analysis.verdict,
      owner: currentActor,
      priority: analysis.riskScore >= 90 ? "critical" : "high",
      status: "open",
      updated: "Just now",
      sla: "5m acknowledge target",
      summary: analysis.summary,
      eventIds: sourceAlert?.evidenceIds || failedEvidence.slice(0, 2).map((event) => event.id),
      sourceAlertId: sourceAlert?.sourceAlertId,
    });
    if (created) {
      setSelectedIncidentId(created.id);
      navigate(SOC_ROUTES.incidents);
    }
  }

  return (
    <>
      <PageHeader
        title="AI Assistant"
        description="Ask questions, inspect supporting evidence, and prepare analyst-reviewed actions from your security data."
        actions={<span className="assist-pill"><ShieldCheck size={15} />Human approval required</span>}
      />

      <div className="ai-assistant-layout">
        <Panel
          className="ai-chat-panel"
          title="Chat with AI Assistant"
          subtitle={`${questionCount} analyst question${questionCount === 1 ? "" : "s"} in this session`}
          actions={<button className="soc-button secondary compact" type="button" disabled={messages.length === 1 || running || mutation.loading} onClick={() => { setMessages([STARTER_MESSAGE]); setLastAnalysis(null); setError(""); }}>Clear chat</button>}
        >
          <div className="ai-message-list" aria-label="Scrollable AI conversation" aria-live="polite" role="region" tabIndex="0" ref={messageListRef}>
            {messages.map((message) => (
              <article className={`ai-message ${message.role}`} key={message.id}>
                <span className="ai-message-avatar" aria-hidden="true">{message.role === "assistant" ? <Bot size={16} /> : "You"}</span>
                <div className="ai-message-content">
                  <p>{message.body}</p>
                  {message.analysis && (
                    <>
                      <div className="ai-answer-summary">
                        <div><SeverityBadge severity={message.analysis.riskScore >= 90 ? "critical" : "high"} /><strong>{message.analysis.verdict}</strong></div>
                        <RiskMeter value={message.analysis.riskScore} />
                      </div>
                      <div className="ai-evidence-table-wrap" role="region" aria-label="Scrollable AI evidence results" tabIndex="0">
                        <table className="ai-evidence-table">
                          <caption>Related failed authentication evidence</caption>
                          <thead><tr><th>Timestamp</th><th>User</th><th>IP address</th><th>Source</th><th>Severity</th></tr></thead>
                          <tbody>{failedEvidence.map((event) => <tr key={event.id}><td>{formatTimestamp(event.timestamp)}</td><td>{event.user || "—"}</td><td className="mono">{event.sourceIp}</td><td>{event.source}</td><td><SeverityBadge severity={event.severity} /></td></tr>)}{!failedEvidence.length && <tr><td colSpan="5">No failed authentication evidence is available.</td></tr>}</tbody>
                        </table>
                      </div>
                      <div className="ai-evidence-chips">{message.analysis.evidence.slice(0, 3).map((item) => <span key={item}>{item}</span>)}</div>
                      <div className="ai-quick-actions">
                        <button type="button" disabled={running || !aiEnabled} onClick={() => askQuestion(`Explain why ${message.analysis.subject} is suspicious`)}>Why is this suspicious?</button>
                        <button type="button" onClick={() => navigate(SOC_ROUTES.alerts)}>Show related alerts</button>
                        <button type="button" disabled={!canWrite || mutation.loading || (repositoryMode === "api" && !incidents.length)} title={!canWrite ? "Viewer access is read-only." : repositoryMode === "api" && !incidents.length ? "Create an incident first." : undefined} onClick={() => copyToNotes(message.analysis)}>Copy to notes</button>
                        <button type="button" disabled={!canWrite || mutation.loading || (repositoryMode === "api" && !availableSourceAlert)} title={!canWrite ? "Viewer access is read-only." : repositoryMode === "api" && !availableSourceAlert ? "No unlinked persisted alert is available." : undefined} onClick={() => createDraftIncident(message.analysis)}>Create draft incident</button>
                      </div>
                    </>
                  )}
                </div>
              </article>
            ))}
            {running && <article className="ai-message assistant"><span className="ai-message-avatar"><Bot size={16} /></span><div className="ai-message-content ai-thinking"><span className="soc-spinner small" /><p>Correlating alerts, events, rules, and incident context…</p></div></article>}
          </div>

          {!aiEnabled && <InlineNotice className="analysis-notice" tone="warning" title="AI assistant is disabled">Enable the AI assistant in Settings before starting an analysis.</InlineNotice>}
          {error && <InlineNotice className="analysis-notice" tone="error" title="Analysis could not run">{error}</InlineNotice>}
          <form className="ai-chat-input" onSubmit={submitQuestion}>
            <label className="sr-only" htmlFor="ai-question">Ask about your security data</label>
            <input id="ai-question" value={prompt} disabled={!aiEnabled} onChange={(event) => setPrompt(event.target.value)} maxLength="500" placeholder="Ask anything about your security data…" />
            <button type="submit" disabled={!prompt.trim() || running || !aiEnabled} aria-label="Send question"><Send size={17} /></button>
          </form>
          <p className="ai-disclaimer">AI output can be incomplete or incorrect. Confirm evidence before changing security state.</p>
        </Panel>

        <Panel className="ai-recommendations" title="AI Recommendations" subtitle="Prioritized workspace improvements">
          <div className="recommendation-list">
            {recommendations.map(({ icon: Icon, title, detail, label, route }) => (
              <article key={title}>
                <span><Icon size={18} /></span>
                <div><strong>{title}</strong><p>{detail}</p></div>
                <button className="soc-button secondary compact" type="button" onClick={() => navigate(route)}>{label}</button>
              </article>
            ))}
          </div>
        </Panel>

        <div className="ai-context-column">
          <Panel title="Conversation Context">
            <dl className="ai-context-list">
              <div><Database size={17} /><dt>Data source</dt><dd>Live workspace data</dd></div>
              <div><CalendarDays size={17} /><dt>Time range</dt><dd>Last 24 hours</dd></div>
              <div><ListChecks size={17} /><dt>Events analyzed</dt><dd>{events.length.toLocaleString()} normalized</dd></div>
              <div><AlertTriangle size={17} /><dt>Active alerts</dt><dd>{activeAlertCount}</dd></div>
              <div><UserRound size={17} /><dt>Analyst</dt><dd>{currentActor}</dd></div>
            </dl>
          </Panel>
          <Panel title="Suggested Prompts">
            <div className="suggested-prompt-list">
              {SUGGESTED_PROMPTS.map((item) => <button type="button" key={item} onClick={() => askQuestion(item)} disabled={running || !aiEnabled}><MessageSquareText size={14} />{item}</button>)}
            </div>
          </Panel>
        </div>
      </div>

      <Panel className="ai-how-it-works" title="How it works" subtitle="A review-first workflow for security analysis">
        <ol>
          <li><span>1</span><MessageSquareText size={18} /><div><strong>Ask a question</strong><p>Use natural language, an event ID, an incident ID, or an IP address.</p></div></li>
          <li><span>2</span><Sparkles size={18} /><div><strong>AI analyzes data</strong><p>This frontend preview correlates the workspace data already loaded for the signed-in analyst.</p></div></li>
          <li><span>3</span><KeyRound size={18} /><div><strong>Review insights and actions</strong><p>An analyst verifies evidence before saving notes or creating a draft incident.</p></div></li>
        </ol>
      </Panel>
    </>
  );
}
