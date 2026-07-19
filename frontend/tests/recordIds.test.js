import test from "node:test";
import assert from "node:assert/strict";
import { nextIncidentId, nextSequentialId } from "../src/soc/utils/recordIds.js";

test("creates the next incident identifier from the highest existing value", () => {
  assert.equal(nextIncidentId([{ id: "INC-1042" }, { id: "INC-1031" }]), "INC-1043");
  assert.equal(nextIncidentId([]), "INC-1000");
});

test("ignores malformed and unrelated identifiers", () => {
  const records = [{ id: "INC-latest" }, { id: "ALT-9999" }, { id: `INC-${"9".repeat(100)}` }, { id: "INC-1004" }, null];
  assert.equal(nextIncidentId(records), "INC-1005");
  assert.equal(nextSequentialId([{ id: "CASE-9" }], "CASE-", 1, 3), "CASE-010");
});
