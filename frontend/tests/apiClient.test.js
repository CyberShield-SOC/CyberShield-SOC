import test from "node:test";
import assert from "node:assert/strict";
import { apiRequest, SESSION_EXPIRED_MESSAGE, shouldBroadcastUnauthorized } from "../src/services/apiClient.js";

test("broadcasts an expired session only for protected API requests", () => {
  assert.equal(shouldBroadcastUnauthorized("/alerts", 401), true);
  assert.equal(shouldBroadcastUnauthorized("/api/incidents?status=open", 401), true);
  assert.equal(shouldBroadcastUnauthorized("/auth/login", 401), false);
  assert.equal(shouldBroadcastUnauthorized("/api/auth/login", 401), false);
  assert.equal(shouldBroadcastUnauthorized("/auth/me", 401, false), false);
  assert.equal(shouldBroadcastUnauthorized("/alerts", 403), false);
});

test("uses one bounded, user-safe session expiration message", () => {
  assert.equal(SESSION_EXPIRED_MESSAGE, "Your session expired. Sign in again to continue.");
});

test("does not announce expiration during the first current-session check", async () => {
  const originalFetch = globalThis.fetch;
  const originalWindow = globalThis.window;
  const windowTarget = new EventTarget();
  let expirationEvents = 0;
  windowTarget.addEventListener("cybershield:unauthorized", () => { expirationEvents += 1; });
  globalThis.window = windowTarget;
  globalThis.fetch = async () => new Response(JSON.stringify({ detail: "Not authenticated" }), {
    headers: { "Content-Type": "application/json" },
    status: 401,
  });

  try {
    await assert.rejects(apiRequest("/auth/me", { broadcastUnauthorizedErrors: false }));
    assert.equal(expirationEvents, 0);
    await assert.rejects(apiRequest("/alerts"));
    assert.equal(expirationEvents, 1);
  } finally {
    globalThis.fetch = originalFetch;
    if (originalWindow === undefined) delete globalThis.window;
    else globalThis.window = originalWindow;
  }
});
