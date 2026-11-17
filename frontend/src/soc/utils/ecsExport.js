import { apiRequestBlob } from "../../services/apiClient.js";
import { downloadBlobFile } from "./eventUtils.js";

// Server-side Elastic Common Schema export (GET /events/export and
// /alerts/export). The server maps stored records to ECS; this only builds
// the request and saves the NDJSON file it returns.
const UPLOAD_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const EXPORT_KINDS = Object.freeze(["events", "alerts"]);

export function ecsExportPath(kind, { uploadId } = {}) {
  if (!EXPORT_KINDS.includes(kind)) throw new Error("Choose events or alerts to export.");
  const params = new URLSearchParams({ format: "ecs" });
  const safeUploadId = String(uploadId || "").trim();
  if (safeUploadId) {
    if (!UPLOAD_ID_PATTERN.test(safeUploadId)) {
      throw new Error("That uploaded file identifier is invalid. Refresh and try again.");
    }
    params.set("upload_id", safeUploadId);
  }
  return `/${kind}/export?${params}`;
}

export function ecsExportSummary({ count, truncated, filename }) {
  const total = Number.isFinite(count) ? count : 0;
  if (!total) return "Nothing to export: this upload has no stored records.";
  const noun = total === 1 ? "record" : "records";
  const saved = `Saved ${total.toLocaleString("en-US")} ${noun} to ${filename}.`;
  return truncated
    ? `${saved} The export stops at 50,000 records, so this file is incomplete.`
    : saved;
}

export async function exportEcs(kind, { uploadId } = {}) {
  const { blob, filename, headers } = await apiRequestBlob(ecsExportPath(kind, { uploadId }), {
    headers: { Accept: "application/x-ndjson" },
  });
  const count = Number(headers?.get("x-export-count"));
  const truncated = headers?.get("x-export-truncated") === "true";
  const safeFilename = filename || `cybershield-${kind}-ecs-${new Date().toISOString().slice(0, 10)}.ndjson`;
  if (blob.size > 0) downloadBlobFile(blob, safeFilename);
  return {
    count: Number.isFinite(count) ? count : null,
    truncated,
    filename: safeFilename,
    empty: blob.size === 0,
  };
}
