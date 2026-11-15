const LABELS = { state: "State", status: "Status", assigned_user_id: "Assignee", resolution_reason: "Resolution reason", resolution_note: "Resolution note", resolved_by_name: "Resolved by", title: "Title", priority: "Priority", alert_id: "Alert", note_id: "Note" };

function display(value) {
  if (value === null || value === undefined || value === "") return "Not recorded";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

export function normalizeWorkflowEvent(event) {
  const before = event.before || {};
  const after = event.after || {};
  const changes = Object.keys(LABELS).filter((key) => Object.hasOwn(after, key) && JSON.stringify(before[key]) !== JSON.stringify(after[key]))
    .map((key) => ({ label: LABELS[key], before: display(before[key]), after: display(after[key]) }));
  const actor = event.actor_name || "Unknown analyst";
  return {
    id: `HISTORY-${event.id}`, at: event.occurred_at,
    title: String(event.event_type || "Recorded change").replaceAll("_", " ").toLowerCase(),
    actor, reason: event.reason || "", note: event.note || "", changes,
    before, after,
    detail: [actor, event.reason, event.note, ...changes.map((change) => `${change.label}: ${change.before} → ${change.after}`)].filter(Boolean).join(" · "),
  };
}
