const LABELS = { notify_slack: "Slack notification", auto_incident: "Automatic incident", suggest_playbook: "Response playbook", create_alert: "Alert creation" };

export function describeRuleAction(key, result) {
  if (!result || typeof result !== "object" || Array.isArray(result)) return null;
  const label = LABELS[key] || String(key).replaceAll("_", " ");
  if (result.status === "failed" || result.status === "error") return { tone: "error", text: `${label} failed. Review its configuration and delivery status.` };
  if (key === "notify_slack") {
    if (result.status === "sent") return { tone: "ok", text: "Slack notification sent." };
    if (result.status === "skipped") return { tone: "muted", text: "Slack notification skipped because no webhook is configured." };
  }
  if (key === "auto_incident") {
    const incidentId = Number(result.incident_id);
    if (["created", "already_exists"].includes(result.status)) return { tone: "ok", text: Number.isSafeInteger(incidentId) && incidentId > 0 ? `Incident #${incidentId} ${result.status === "created" ? "created automatically" : "already linked"}.` : "Incident action completed; its identifier was not provided.", incidentId: Number.isSafeInteger(incidentId) && incidentId > 0 ? incidentId : null };
    if (result.status === "threshold_not_met") {
      const count = Number(result.threshold_count), seconds = Number(result.threshold_window_seconds);
      return { tone: "muted", text: `Incident threshold not met${count > 0 && seconds > 0 ? `: requires ${count} events within ${seconds >= 3600 ? `${seconds / 3600}h` : `${seconds / 60}m`}` : ""}.` };
    }
  }
  if (key === "suggest_playbook" && result.status === "linked") return { tone: "ok", text: result.playbook_id ? `Response playbook ${result.playbook_id} linked.` : "Response playbook linked." };
  const status = String(result.status || "not recorded").replaceAll("_", " ");
  return { tone: "muted", text: `${label}: ${status}.` };
}
