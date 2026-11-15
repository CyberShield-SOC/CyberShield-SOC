import test from "node:test";
import assert from "node:assert/strict";
import { exportReportPdf, normalizePdfRange, PDF_RANGE_OPTIONS, REPORT_PDF_SLUGS } from "../src/soc/utils/reportPdfExport.js";

function stubDownload() {
  const previous = { document: globalThis.document, window: globalThis.window, create: URL.createObjectURL, revoke: URL.revokeObjectURL };
  const link = { click() {}, remove() {} };
  globalThis.document = { createElement: () => link, body: { append() {} } };
  globalThis.window = { setTimeout() {} };
  URL.createObjectURL = () => "blob:test";
  URL.revokeObjectURL = () => {};
  return { link, restore: () => { globalThis.document = previous.document; globalThis.window = previous.window; URL.createObjectURL = previous.create; URL.revokeObjectURL = previous.revoke; } };
}

test("the four phase-1 reports map to their PDF-specific backend slugs", () => {
  assert.deepEqual(REPORT_PDF_SLUGS, {
    "Daily SOC operations": "daily-soc-operations",
    "Weekly incident summary": "weekly-incident-summary",
    "Detection coverage": "detection-coverage",
    "Executive risk overview": "executive-risk-overview",
  });
});

test("normalizePdfRange only accepts the backend's three supported presets", () => {
  assert.equal(normalizePdfRange("7d"), "7d");
  assert.equal(normalizePdfRange("30d"), "30d");
  assert.equal(normalizePdfRange("1h"), "24h");
  assert.equal(normalizePdfRange("all"), "24h");
  assert.equal(normalizePdfRange(undefined), "24h");
  assert.deepEqual(PDF_RANGE_OPTIONS, ["24h", "7d", "30d"]);
});

test("rejects an unsupported report name before making a request", async () => {
  await assert.rejects(exportReportPdf("Not a report", "24h"), /supported report/);
});

test("requests the report's slug with the chosen range and downloads the server's suggested filename", async () => {
  const originalFetch = globalThis.fetch;
  let capturedUrl;
  globalThis.fetch = async (url) => {
    capturedUrl = url;
    return new Response(new Blob([new Uint8Array([0x25, 0x50, 0x44, 0x46])]), {
      status: 200,
      headers: {
        "Content-Type": "application/pdf",
        "Content-Disposition": 'attachment; filename="cybershield-detection-coverage-2026-10-25.pdf"',
      },
    });
  };
  const { link, restore } = stubDownload();

  try {
    const result = await exportReportPdf("Detection coverage", "7d");
    assert.match(capturedUrl, /\/reports\/detection-coverage\/pdf\?range=7d$/);
    assert.equal(result.filename, "cybershield-detection-coverage-2026-10-25.pdf");
    assert.equal(link.download, "cybershield-detection-coverage-2026-10-25.pdf");
  } finally {
    globalThis.fetch = originalFetch;
    restore();
  }
});

test("falls back to a generated filename when the server omits Content-Disposition", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response(new Blob([new Uint8Array([0x25, 0x50, 0x44, 0x46])]), { status: 200 });
  const { restore } = stubDownload();

  try {
    const result = await exportReportPdf("Daily SOC operations");
    assert.match(result.filename, /^cybershield-daily-soc-operations-\d{4}-\d{2}-\d{2}\.pdf$/);
  } finally {
    globalThis.fetch = originalFetch;
    restore();
  }
});

test("surfaces a 422 (unsupported range) as a rejected promise rather than downloading", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response(JSON.stringify({ detail: "Unsupported range." }), {
    status: 422,
    headers: { "Content-Type": "application/json" },
  });

  try {
    await assert.rejects(exportReportPdf("Weekly incident summary", "24h"));
  } finally {
    globalThis.fetch = originalFetch;
  }
});
