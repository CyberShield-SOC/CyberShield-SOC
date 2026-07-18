import test from "node:test";
import assert from "node:assert/strict";
import { createInFlightDeduper } from "../src/soc/utils/asyncUtils.js";

test("coalesces matching in-flight reads without caching later refreshes", async () => {
  const runOnce = createInFlightDeduper();
  let resolveRequest;
  let calls = 0;
  const loader = () => {
    calls += 1;
    return new Promise((resolve) => { resolveRequest = resolve; });
  };

  const first = runOnce("events", loader);
  const duplicate = runOnce("events", loader);
  assert.equal(first, duplicate);
  assert.equal(calls, 0);

  await Promise.resolve();
  assert.equal(calls, 1);
  resolveRequest(["record"]);
  assert.deepEqual(await duplicate, ["record"]);

  const refreshed = runOnce("events", async () => ["new record"]);
  assert.notEqual(refreshed, first);
  assert.deepEqual(await refreshed, ["new record"]);
});

test("clears rejected reads so retry is possible", async () => {
  const runOnce = createInFlightDeduper();
  await assert.rejects(runOnce("alerts", async () => { throw new Error("offline"); }), /offline/);
  await assert.doesNotReject(runOnce("alerts", async () => []));
});
