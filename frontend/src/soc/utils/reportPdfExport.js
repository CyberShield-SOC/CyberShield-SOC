import { apiRequestBlob } from "../../services/apiClient.js";
import { downloadBlobFile } from "./eventUtils.js";

// Server-side PDF export (GET /reports/{report_id}/pdf) uses its own slugs,
// distinct from the CSV export filenames in reportExport.js.
export const REPORT_PDF_SLUGS = Object.freeze({
  "Daily SOC operations": "daily-soc-operations",
  "Weekly incident summary": "weekly-incident-summary",
  "Detection coverage": "detection-coverage",
  "Executive risk overview": "executive-risk-overview",
});

// The backend only accepts these three lookback presets for PDF export.
export const PDF_RANGE_OPTIONS = Object.freeze(["24h", "7d", "30d"]);
export const PDF_RANGE_LABELS = Object.freeze({
  "24h": "Last 24 hours",
  "7d": "Last 7 days",
  "30d": "Last 30 days",
});

export function normalizePdfRange(value) {
  return PDF_RANGE_OPTIONS.includes(value) ? value : "24h";
}

export async function exportReportPdf(reportName, range) {
  const slug = REPORT_PDF_SLUGS[reportName];
  if (!slug) throw new Error("Choose a supported report.");
  const normalizedRange = normalizePdfRange(range);

  const { blob, filename } = await apiRequestBlob(`/reports/${slug}/pdf?range=${normalizedRange}`);
  const safeFilename = filename || `cybershield-${slug}-${new Date().toISOString().slice(0, 10)}.pdf`;
  downloadBlobFile(blob, safeFilename);
  return { filename: safeFilename };
}
