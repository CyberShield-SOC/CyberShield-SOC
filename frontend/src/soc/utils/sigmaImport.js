// Client side of Sigma import (POST /custom-rules/import/sigma). The server
// translates the rules (backend/app/services/sigma_import.py); this checks
// the file before sending and shapes the per-rule results for display.

export const MAX_SIGMA_BYTES = 262_144;
export const SIGMA_FILE_ACCEPT = ".yml,.yaml,text/yaml,application/x-yaml,text/plain";

const SIGMA_EXTENSION = /\.(ya?ml|txt)$/i;
const RESULT_STATES = new Set(["created", "skipped", "rejected"]);

export function validateSigmaFile(file) {
  if (!file) return "Choose a Sigma rule file.";
  if (!SIGMA_EXTENSION.test(file.name || "")) return "Sigma rules must be a .yml or .yaml file.";
  if (!file.size) return "That file is empty.";
  if (file.size > MAX_SIGMA_BYTES) return "An import is limited to 256 KB of YAML.";
  return "";
}

export function validateSigmaText(text) {
  const content = String(text || "");
  if (!content.trim()) return "Paste one or more Sigma rules, or load a .yml file.";
  if (new Blob([content]).size > MAX_SIGMA_BYTES) return "An import is limited to 256 KB of YAML.";
  if (!/^\s*title\s*:/m.test(content) || !/^\s*detection\s*:/m.test(content)) {
    return "That does not look like a Sigma rule: it needs a title and a detection section.";
  }
  return "";
}

export function normalizeSigmaImport(payload, normalizeRule = (rule) => rule) {
  const results = (Array.isArray(payload?.results) ? payload.results : [])
    .filter((item) => RESULT_STATES.has(item?.status))
    .map((item) => ({
      title: String(item.title || "Untitled rule"),
      status: item.status,
      ruleId: item.rule_id ? String(item.rule_id) : "",
      reason: String(item.reason || ""),
      notes: Array.isArray(item.notes) ? item.notes.map(String) : [],
      rule: item.rule ? normalizeRule(item.rule) : null,
    }));
  const count = (state) => results.filter((item) => item.status === state).length;
  return { created: count("created"), skipped: count("skipped"), rejected: count("rejected"), results };
}

export function sigmaImportSummary({ created, skipped, rejected }) {
  const parts = [];
  if (created) parts.push(`${created} imported as ${created === 1 ? "a draft" : "drafts"}`);
  if (skipped) parts.push(`${skipped} already imported`);
  if (rejected) parts.push(`${rejected} could not be translated`);
  return parts.length ? `${parts.join(", ")}.` : "No rules were found in that YAML.";
}
