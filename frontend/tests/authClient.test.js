import test from "node:test";
import assert from "node:assert/strict";
import {
  authClient,
  AuthRequestError,
  getAuthFailureMessage,
  readAuthUser,
} from "../src/services/authClient.js";
import { getAccessToken, setAccessToken } from "../src/services/apiClient.js";

const VALID_USER = {
  id: 1,
  username: "analyst",
  email: "analyst@cybershield.io",
  is_active: true,
  role: "Analyst",
};

function withMockedFetch(handler, run) {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = handler;
  return run().finally(() => {
    globalThis.fetch = originalFetch;
  });
}

test("uses a privacy-preserving message for rejected credentials", () => {
  assert.equal(
    getAuthFailureMessage(401),
    "The username or password you entered is incorrect",
  );
});

test("keeps throttling and service failures distinct", () => {
  assert.match(getAuthFailureMessage(429), /Too many sign-in attempts/);
  assert.match(getAuthFailureMessage(503), /secure service could not complete/);
});

test("rejects malformed successful authentication responses", () => {
  assert.throws(() => readAuthUser({ user: null }), AuthRequestError);
  assert.throws(() => readAuthUser({ user: { id: 1 } }), AuthRequestError);
  assert.equal(readAuthUser({
    user: {
      id: 1,
      username: "analyst",
      email: "analyst@cybershield.io",
      is_active: true,
      role: "Analyst",
    },
  }).username, "analyst");
  assert.throws(() => readAuthUser({
    user: {
      id: 1,
      username: "analyst",
      email: "analyst@cybershield.io",
      is_active: true,
      role: "Owner",
    },
  }), AuthRequestError);
});

test("login stores the JWT access token in memory for later requests", async () => {
  await withMockedFetch(
    async () => new Response(
      JSON.stringify({
        success: true,
        access_token: "fresh-jwt",
        token_type: "bearer",
        expires_in: 600,
        user: VALID_USER,
      }),
      { headers: { "Content-Type": "application/json" }, status: 200 },
    ),
    async () => {
      setAccessToken(null);
      const user = await authClient.login({ email: VALID_USER.email, password: "correct-horse" });
      assert.equal(user.username, "analyst");
      assert.equal(getAccessToken(), "fresh-jwt");
      setAccessToken(null);
    },
  );
});

test("refresh mints a new access token from the refresh cookie and never throws", async () => {
  await withMockedFetch(
    async () => new Response(
      JSON.stringify({
        success: true,
        access_token: "rotated-jwt",
        token_type: "bearer",
        expires_in: 600,
        user: VALID_USER,
      }),
      { headers: { "Content-Type": "application/json" }, status: 200 },
    ),
    async () => {
      setAccessToken(null);
      const user = await authClient.refresh();
      assert.equal(user.username, "analyst");
      assert.equal(getAccessToken(), "rotated-jwt");
      setAccessToken(null);
    },
  );
});

test("refresh clears the access token and resolves null on failure, without throwing", async () => {
  await withMockedFetch(
    async () => new Response(
      JSON.stringify({ detail: "Invalid or expired refresh token" }),
      { headers: { "Content-Type": "application/json" }, status: 401 },
    ),
    async () => {
      setAccessToken("stale-jwt");
      const user = await authClient.refresh();
      assert.equal(user, null);
      assert.equal(getAccessToken(), null);
    },
  );
});

test("logout always clears the in-memory access token, even if the request fails", async () => {
  await withMockedFetch(
    async () => new Response(JSON.stringify({ detail: "boom" }), {
      headers: { "Content-Type": "application/json" },
      status: 500,
    }),
    async () => {
      setAccessToken("about-to-log-out");
      await assert.rejects(authClient.logout());
      assert.equal(getAccessToken(), null);
    },
  );
});
