import test from "node:test";
import assert from "node:assert/strict";
import {
  AUTH_ROUTES,
  canAccessSocRoute,
  isSocRoute,
  normalizeAppRoute,
  normalizeAuthRoute,
  shouldRejectUninitiatedMfa,
  shouldRedirectAuthenticatedLogin,
  SOC_ROUTES,
} from "../src/hooks/useAuthRoute.js";

test("normalizes supported display routes", () => {
  assert.equal(normalizeAuthRoute("#/login"), AUTH_ROUTES.login);
  assert.equal(normalizeAuthRoute("#/forgot-password"), AUTH_ROUTES.forgotPassword);
  assert.equal(normalizeAuthRoute("#/access-granted"), AUTH_ROUTES.login);
});

test("falls back safely for unknown routes", () => {
  assert.equal(normalizeAuthRoute("#/unknown"), AUTH_ROUTES.login);
  assert.equal(normalizeAuthRoute(""), AUTH_ROUTES.login);
});

test("normalizes application routes and ignores query parameters", () => {
  assert.equal(normalizeAppRoute("#/dashboard"), SOC_ROUTES.dashboard);
  assert.equal(normalizeAppRoute("#/event-logs?q=203.0.113.88"), SOC_ROUTES.eventLogs);
  assert.equal(normalizeAppRoute("#/ai-analysis"), SOC_ROUTES.aiAnalysis);
  assert.equal(normalizeAppRoute("#/analyst-notes"), SOC_ROUTES.analystNotes);
  assert.equal(normalizeAppRoute("#/quick-resolve"), SOC_ROUTES.quickResolve);
  assert.equal(normalizeAppRoute("#/help"), SOC_ROUTES.help);
  assert.equal(normalizeAppRoute("#/logout-success"), AUTH_ROUTES.logoutSuccess);
  assert.equal(normalizeAppRoute("#/not-a-route"), AUTH_ROUTES.login);
  assert.equal(isSocRoute(SOC_ROUTES.incidents), true);
  assert.equal(isSocRoute(AUTH_ROUTES.login), false);
});

test("redirects only an authenticated login route into the SOC", () => {
  assert.equal(
    shouldRedirectAuthenticatedLogin(AUTH_ROUTES.login, "authenticated"),
    true,
  );
  assert.equal(
    shouldRedirectAuthenticatedLogin(AUTH_ROUTES.login, "checking"),
    false,
  );
  assert.equal(
    shouldRedirectAuthenticatedLogin(AUTH_ROUTES.mfa, "authenticated"),
    false,
  );
  assert.equal(
    shouldRedirectAuthenticatedLogin(AUTH_ROUTES.logoutSuccess, "authenticated"),
    false,
  );
});

test("rejects a direct anonymous MFA route without a primary-login challenge", () => {
  assert.equal(
    shouldRejectUninitiatedMfa(AUTH_ROUTES.mfa, "anonymous", false),
    true,
  );
  assert.equal(
    shouldRejectUninitiatedMfa(AUTH_ROUTES.mfa, "anonymous", true),
    false,
  );
  assert.equal(
    shouldRejectUninitiatedMfa(AUTH_ROUTES.mfa, "authenticated", false),
    false,
  );
});

test("limits the user-management route to connected administrators", () => {
  assert.equal(canAccessSocRoute(SOC_ROUTES.users, { role: "Admin" }), true);
  assert.equal(canAccessSocRoute(SOC_ROUTES.users, { role: "Analyst" }), false);
  assert.equal(canAccessSocRoute(SOC_ROUTES.users, null), true);
  assert.equal(canAccessSocRoute(SOC_ROUTES.dashboard, { role: "Viewer" }), true);
  assert.equal(canAccessSocRoute(AUTH_ROUTES.login, { role: "Admin" }), false);
});
