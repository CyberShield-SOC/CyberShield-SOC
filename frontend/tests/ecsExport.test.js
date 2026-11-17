import assert from "node:assert/strict";
import test from "node:test";

import { ecsExportPath, ecsExportSummary } from "../src/soc/utils/ecsExport.js";

const UPLOAD_ID = "0b0e7c06-6f0f-4d0e-9a53-0d6a4b0f3f11";

test("ECS export paths name the format and the upload", () => {
  assert.equal(ecsExportPath("events"), "/events/export?format=ecs");
  assert.equal(ecsExportPath("alerts", { uploadId: UPLOAD_ID }), `/alerts/export?format=ecs&upload_id=${UPLOAD_ID}`);
  assert.equal(ecsExportPath("events", { uploadId: `  ${UPLOAD_ID} ` }), `/events/export?format=ecs&upload_id=${UPLOAD_ID}`);
});

test("ECS export refuses unknown record kinds and malformed upload ids", () => {
  assert.throws(() => ecsExportPath("users"), /events or alerts/);
  assert.throws(() => ecsExportPath("events", { uploadId: "1 OR 1=1" }), /identifier is invalid/);
});

test("ECS export summary reports the count and flags a capped file", () => {
  assert.equal(
    ecsExportSummary({ count: 1, truncated: false, filename: "a.ndjson" }),
    "Saved 1 record to a.ndjson.",
  );
  assert.equal(
    ecsExportSummary({ count: 1284, truncated: false, filename: "a.ndjson" }),
    "Saved 1,284 records to a.ndjson.",
  );
  assert.match(
    ecsExportSummary({ count: 50000, truncated: true, filename: "a.ndjson" }),
    /^Saved 50,000 records to a\.ndjson\. The export stops at 50,000 records, so this file is incomplete\.$/,
  );
  assert.equal(
    ecsExportSummary({ count: 0, truncated: false, filename: "a.ndjson" }),
    "Nothing to export: this upload has no stored records.",
  );
  assert.equal(
    ecsExportSummary({ count: null, truncated: false, filename: "a.ndjson" }),
    "Nothing to export: this upload has no stored records.",
  );
});
