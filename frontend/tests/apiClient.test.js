import test from "node:test";
import assert from "node:assert/strict";
import {
  apiRequest,
  getAccessToken,
  setAccessToken,
  setUnauthorizedRefreshHandler,
  SESSION_EXPIRED_MESSAGE,
  shouldBroadcastUnauthorized,
} from "../src/services/apiClient.js";

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

test("attaches the Authorization header once an access token is set", async () => {
  const originalFetch = globalThis.fetch;
  let capturedAuthorization;
  globalThis.fetch = async (_url, options) => {
    capturedAuthorization = options.headers.get("Authorization");
    return new Response(JSON.stringify({ ok: true }), {
      headers: { "Content-Type": "application/json" },
      status: 200,
    });
  };

  try {
    setAccessToken(null);
    await apiRequest("/alerts");
    assert.equal(capturedAuthorization, null);

    setAccessToken("a-jwt-access-token");
    await apiRequest("/alerts");
    assert.equal(capturedAuthorization, "Bearer a-jwt-access-token");
  } finally {
    globalThis.fetch = originalFetch;
    setAccessToken(null);
  }
});

test("never invokes the refresh handler for the refresh endpoint's own 401 (no recursion)", async () => {
  const originalFetch = globalThis.fetch;
  let handlerCalls = 0;
  globalThis.fetch = async () => new Response(JSON.stringify({ detail: "Invalid or expired refresh token" }), {
    headers: { "Content-Type": "application/json" },
    status: 401,
  });
  setUnauthorizedRefreshHandler(() => {
    handlerCalls += 1;
    return Promise.resolve(null);
  });

  try {
    await assert.rejects(apiRequest("/auth/refresh", { method: "POST", broadcastUnauthorizedErrors: false }));
    assert.equal(handlerCalls, 0);
  } finally {
    globalThis.fetch = originalFetch;
    setUnauthorizedRefreshHandler(null);
  }
});

test("retries a resource request once via the refresh handler, then succeeds", async () => {
  const originalFetch = globalThis.fetch;
  let handlerCalls = 0;
  let fetchCalls = 0;
  globalThis.fetch = async () => {
    fetchCalls += 1;
    if (fetchCalls === 1) {
      return new Response(JSON.stringify({ detail: "Not authenticated" }), {
        headers: { "Content-Type": "application/json" },
        status: 401,
      });
    }
    return new Response(JSON.stringify({ items: [] }), {
      headers: { "Content-Type": "application/json" },
      status: 200,
    });
  };
  setUnauthorizedRefreshHandler(() => {
    handlerCalls += 1;
    setAccessToken("rotated-jwt");
    return Promise.resolve({ id: 1, username: "analyst" });
  });

  try {
    const payload = await apiRequest("/alerts");
    assert.deepEqual(payload, { items: [] });
    assert.equal(handlerCalls, 1);
    assert.equal(fetchCalls, 2);
    assert.equal(getAccessToken(), "rotated-jwt");
  } finally {
    globalThis.fetch = originalFetch;
    setUnauthorizedRefreshHandler(null);
    setAccessToken(null);
  }
});

test("gives up and broadcasts the expired session when the refresh handler cannot recover it", async () => {
  const originalFetch = globalThis.fetch;
  const originalWindow = globalThis.window;
  const windowTarget = new EventTarget();
  let expirationEvents = 0;
  let handlerCalls = 0;
  windowTarget.addEventListener("cybershield:unauthorized", () => { expirationEvents += 1; });
  globalThis.window = windowTarget;
  globalThis.fetch = async () => new Response(JSON.stringify({ detail: "Not authenticated" }), {
    headers: { "Content-Type": "application/json" },
    status: 401,
  });
  setUnauthorizedRefreshHandler(() => {
    handlerCalls += 1;
    return Promise.resolve(null);
  });

  try {
    await assert.rejects(apiRequest("/alerts"));
    assert.equal(handlerCalls, 1);
    assert.equal(expirationEvents, 1);
  } finally {
    globalThis.fetch = originalFetch;
    setUnauthorizedRefreshHandler(null);
    if (originalWindow === undefined) delete globalThis.window;
    else globalThis.window = originalWindow;
  }
});
