const TEXT_ENTRY_TAGS = new Set(["INPUT", "TEXTAREA", "SELECT"]);

function isTextEntry(target) {
  return Boolean(
    target
    && (TEXT_ENTRY_TAGS.has(target.tagName) || target.isContentEditable),
  );
}

/**
 * Global search supports the familiar Ctrl/Cmd+K command and a lightweight
 * slash shortcut when the analyst is not already typing in another control.
 */
export function shouldFocusGlobalSearch(event) {
  if (!event || event.altKey || event.repeat) return false;
  const key = String(event.key || "").toLowerCase();
  if (key === "k" && (event.ctrlKey || event.metaKey)) return true;
  return key === "/" && !event.ctrlKey && !event.metaKey && !isTextEntry(event.target);
}

export function searchShortcutLabel(platform = "") {
  return /mac|iphone|ipad/i.test(platform) ? "⌘ K" : "Ctrl K";
}
