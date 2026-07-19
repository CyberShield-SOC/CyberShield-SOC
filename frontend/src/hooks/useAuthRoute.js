import { useCallback, useEffect, useState } from "react";
import { canOpenUserManagement } from "../utils/permissions.js";

export const AUTH_ROUTES = Object.freeze({
  login: "login",
  mfa: "mfa",
  forgotPassword: "forgot-password",
  sso: "uta-sso",
  support: "support",
  logoutSuccess: "logout-success",
});

const VALID_AUTH_ROUTES = new Set(Object.values(AUTH_ROUTES));

export const SOC_ROUTES = Object.freeze({
  dashboard: "dashboard",
  eventLogs: "event-logs",
  threatDetection: "threat-detection",
  alerts: "alerts",
  incidents: "incidents",
  incidentTracking: "incident-tracking",
  quickResolve: "quick-resolve",
  aiAnalysis: "ai-analysis",
  analystNotes: "analyst-notes",
  reports: "reports",
  manage: "manage",
  users: "users",
  integrations: "integrations",
  settings: "settings",
  help: "help",
});

const VALID_APP_ROUTES = new Set([
  ...Object.values(AUTH_ROUTES),
  ...Object.values(SOC_ROUTES),
]);

const VALID_SOC_ROUTES = new Set(Object.values(SOC_ROUTES));

function routeFromHash(hash) {
  return String(hash || "")
    .replace(/^#\/?/, "")
    .split(/[?&]/, 1)[0];
}

export function normalizeAuthRoute(hash) {
  const route = routeFromHash(hash);
  return VALID_AUTH_ROUTES.has(route) ? route : AUTH_ROUTES.login;
}

export function normalizeAppRoute(hash) {
  const route = routeFromHash(hash);
  return VALID_APP_ROUTES.has(route) ? route : AUTH_ROUTES.login;
}

export function isSocRoute(route) {
  return VALID_SOC_ROUTES.has(route);
}

export function canAccessSocRoute(route, user) {
  if (!isSocRoute(route)) return false;
  if (route !== SOC_ROUTES.users) return true;
  return canOpenUserManagement(user);
}

export function shouldRedirectAuthenticatedLogin(route, sessionStatus) {
  return route === AUTH_ROUTES.login && sessionStatus === "authenticated";
}

export function shouldRejectUninitiatedMfa(route, sessionStatus, mfaPending) {
  return (
    route === AUTH_ROUTES.mfa
    && sessionStatus === "anonymous"
    && !mfaPending
  );
}

export function useAuthRoute() {
  const [route, setRoute] = useState(() => normalizeAppRoute(window.location.hash));

  useEffect(() => {
    if (!window.location.hash) {
      window.history.replaceState(null, "", `#/${AUTH_ROUTES.login}`);
    }

    function handleHashChange() {
      setRoute(normalizeAppRoute(window.location.hash));
    }

    window.addEventListener("hashchange", handleHashChange);
    return () => window.removeEventListener("hashchange", handleHashChange);
  }, []);

  const navigate = useCallback((nextRoute) => {
    const safeRoute = normalizeAppRoute(`#/${nextRoute}`);
    const nextHash = `#/${safeRoute}`;

    if (window.location.hash === nextHash) {
      setRoute(safeRoute);
      return;
    }

    // Update React state in the same turn as the URL. This prevents guarded
    // routes from briefly observing a signed-out session on the previous route.
    setRoute(safeRoute);
    window.location.hash = nextHash;
  }, []);

  return { route, navigate };
}
