const NAVIGATION_BADGE_LIMIT = 99;

/**
 * Keep compact navigation badges from widening the sidebar at high volume.
 * Callers retain the exact count in their accessible label.
 */
export function formatNavigationBadgeCount(value) {
  const count = Number(value);
  if (!Number.isFinite(count) || count <= 0) return "0";

  const normalizedCount = Math.floor(count);
  return normalizedCount > NAVIGATION_BADGE_LIMIT
    ? `${NAVIGATION_BADGE_LIMIT}+`
    : String(normalizedCount);
}
