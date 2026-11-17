import { apiRequestBlob } from "../../services/apiClient.js";
import { downloadBlobFile } from "./eventUtils.js";

// Matches MAX_FEED_BYTES in backend/app/routers/threat_intel.py.
export const MAX_FEED_FILE_BYTES = 10 * 1024 * 1024;
export const FEED_FILE_ACCEPT = ".txt,.csv,.json,.stix,text/plain,application/json";

const FEED_FILE_EXTENSION = /\.(txt|csv|json|stix)$/i;
const SUPPORTED_STIX_COMPARISON = /\b(?:ipv4-addr|ipv6-addr|domain-name):value\s*(?:=|ISSUBSET)\s*'/i;

/** A feed is read as STIX when it opens with "{", as the server decides it. */
export function isStixContent(content) {
  return String(content || "").replace(/^[﻿\s]+/, "").startsWith("{");
}

export function validateFeedFile(file) {
  if (!file) return "Choose a feed file.";
  if (!FEED_FILE_EXTENSION.test(file.name || "")) return "Feed files must be .txt, .csv, .json, or .stix.";
  if (!file.size) return "That file is empty.";
  if (file.size > MAX_FEED_FILE_BYTES) return "Feed files are limited to 10 MB.";
  return "";
}

/** "Abuse CH (2026).stix.json" -> "Abuse-CH-2026", a name the server accepts. */
export function feedNameFromFilename(filename) {
  return String(filename || "")
    .replace(/(\.stix)?\.(txt|csv|json|stix)$/i, "")
    .replace(/[^A-Za-z0-9 ._:-]+/g, " ")
    .trim()
    .replace(/\s+/g, "-")
    .replace(/^[^A-Za-z0-9]+/, "")
    .slice(0, 100);
}

/** Sample-mode stand-in for the server's STIX reader: counts, nothing stored. */
export function summarizeStixBundle(content) {
  let bundle;
  try {
    bundle = JSON.parse(String(content || "").replace(/^﻿/, ""));
  } catch {
    throw new Error("The feed looks like JSON but could not be read.");
  }
  if (bundle?.type !== "bundle" || !Array.isArray(bundle.objects)) {
    throw new Error("JSON feeds must be a STIX 2.1 bundle with an objects list.");
  }
  const indicators = bundle.objects.filter((item) => item?.type === "indicator");
  const usable = indicators.filter((item) => (
    typeof item.pattern === "string"
    && (item.pattern_type || "stix") === "stix"
    && item.revoked !== true
    && SUPPORTED_STIX_COMPARISON.test(item.pattern)
  ));
  return { imported: usable.length, rejected: indicators.length - usable.length };
}

export function feedImportSummary({ source, imported, rejectedLines, format }) {
  const noun = imported === 1 ? "indicator" : "indicators";
  const origin = format === "stix" ? " from the STIX bundle" : "";
  const skipped = rejectedLines
    ? format === "stix"
      ? ` ${rejectedLines} STIX ${rejectedLines === 1 ? "indicator was" : "indicators were"} skipped: only IPs, ranges, and domains can be matched.`
      : ` Skipped ${rejectedLines} unrecognized ${rejectedLines === 1 ? "line" : "lines"}.`
    : "";
  return `Imported ${imported} ${noun}${origin} into "${source}".${skipped}`;
}

export async function exportThreatFeedStix(source) {
  const safeSource = String(source || "").trim();
  if (!safeSource) throw new Error("Choose a feed to export.");
  const { blob, filename } = await apiRequestBlob(`/threat-intel/feeds/${encodeURIComponent(safeSource)}/stix`, {
    headers: { Accept: "application/stix+json" },
  });
  const safeFilename = filename || `${feedNameFromFilename(safeSource) || "threat-feed"}.stix.json`;
  downloadBlobFile(blob, safeFilename);
  return { filename: safeFilename };
}
