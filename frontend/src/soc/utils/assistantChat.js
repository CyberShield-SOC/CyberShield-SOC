// Limits mirror backend/app/routers/assistant.py (MAX_MESSAGES / MAX_MESSAGE_CHARS).
export const ASSISTANT_MAX_MESSAGES = 20;
export const ASSISTANT_MAX_MESSAGE_CHARS = 4000;

export const ASSISTANT_TOOL_LABELS = Object.freeze({
  list_alerts: "Alerts",
  list_incidents: "Incidents",
  search_events: "Events",
  auth_activity: "Authentication activity",
  list_users: "Users",
  list_detection_rules: "Detection rules",
});

export function assistantToolLabel(name) {
  return ASSISTANT_TOOL_LABELS[name] || "Workspace data";
}

/**
 * Convert chat-page messages into the API conversation. Only real analyst and
 * assistant turns are sent (the welcome message is UI-only), trimmed to the
 * most recent window, and the API requires it to start with a user turn.
 */
export function buildAssistantHistory(messages) {
  const turns = (Array.isArray(messages) ? messages : [])
    .filter((message) => (message?.role === "user" || message?.role === "assistant") && !message.local)
    .map((message) => ({
      role: message.role,
      content: String(message.body || "").slice(0, ASSISTANT_MAX_MESSAGE_CHARS).trim(),
    }))
    .filter((message) => message.content);

  const recent = turns.slice(-ASSISTANT_MAX_MESSAGES);
  while (recent.length && recent[0].role !== "user") recent.shift();
  return recent;
}
