function validateRequiredLength(value, label, minimum) {
  const normalized = String(value ?? "").trim();

  if (!normalized) return `${label} is required.`;
  if (normalized.length < minimum) return `${label} must be at least ${minimum} characters.`;
  return "";
}

function compactErrors(errors) {
  return Object.fromEntries(Object.entries(errors).filter(([, message]) => Boolean(message)));
}

export function parseNoteTags(value) {
  return [...new Set(
    String(value ?? "")
      .split(",")
      .map((tag) => tag.trim().toLowerCase())
      .filter(Boolean),
  )];
}

/** Client-side guidance only; the backend remains authoritative for validation. */
export function validateAnalystNote({ title, body, tags = "" }) {
  const parsedTags = parseNoteTags(tags);
  return compactErrors({
    title: validateRequiredLength(title, "Title", 4),
    body: validateRequiredLength(body, "Investigation note", 12),
    tags: parsedTags.length > 6
      ? "Use no more than 6 tags."
      : parsedTags.some((tag) => tag.length > 40)
        ? "Each tag must be 40 characters or fewer."
        : "",
  });
}

/** Keeps incident-draft feedback predictable and testable across adapters. */
export function validateIncidentDraft({ title, summary }) {
  return compactErrors({
    title: validateRequiredLength(title, "Title", 4),
    summary: validateRequiredLength(summary, "Summary", 12),
  });
}

export function validateWorkspaceSettings(settings) {
  const workspaceName = String(settings?.workspace?.name ?? "").trim();
  return compactErrors({
    workspaceName: workspaceName ? "" : "Workspace name is required.",
  });
}
