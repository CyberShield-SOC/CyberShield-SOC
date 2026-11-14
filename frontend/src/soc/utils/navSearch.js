// Which sidebar section, if any, a global-search query names.

function singular(word) {
  return word.endsWith("s") ? word.slice(0, -1) : word;
}

/**
 * `targets` is [[route, label], ...] in sidebar order. `canAccess(route)`
 * keeps a Viewer's search for "users" from landing on a page SocApp would
 * bounce them off, with a stale hash left behind: the query falls through
 * to a data search instead.
 *
 * Precedence: the whole label, singular or plural ("alert", "incidents"),
 * then a whole word of a multi-word label ("tracking", "notes"). So
 * "incident" reaches Incidents, not Incident Tracking. Substrings never
 * match: "port" must not open Reports and "ale" must not open Alerts,
 * because those pages drop the query and the search would be stranded.
 */
export function resolveNavDestination(query, targets, canAccess = () => true) {
  const needle = String(query || "").trim().toLowerCase();
  if (needle.length < 2) return null;
  const allowed = targets.filter(([route]) => canAccess(route));
  const byLabel = allowed.find(([, label]) => singular(label.toLowerCase()) === singular(needle));
  if (byLabel) return byLabel[0];
  const byWord = allowed.find(([, label]) => label.toLowerCase().split(" ").includes(needle));
  return byWord ? byWord[0] : null;
}
