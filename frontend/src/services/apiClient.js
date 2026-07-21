// Production builds default to the same-origin FastAPI contract. Developers
// can still set VITE_API_BASE_URL="" explicitly when they need sample mode.
const DEFAULT_API_BASE_URL = import.meta.env?.PROD ? "/api" : "";
const API_BASE_URL = String(import.meta.env?.VITE_API_BASE_URL ?? DEFAULT_API_BASE_URL).replace(/\/$/, "");
const FORCE_SAMPLE_MODE = String(import.meta.env?.VITE_USE_MOCK_DATA || "").toLowerCase() === "true";
const REQUEST_TIMEOUT_MS = 12_000;
const CSRF_COOKIE_NAME = "cybershield_csrf";
const LOGIN_PATHS = new Set(["/auth/login", "/api/auth/login"]);
// Login/refresh/logout are the only cookie-authenticated auth endpoints left.
// A 401 from any of them must never itself trigger another refresh attempt
// (that would recurse) — resource endpoints are the only ones eligible for
// the silent-refresh-and-retry flow below.
const NO_INTERCEPT_PATHS = new Set([
  "/auth/login", "/api/auth/login",
  "/auth/refresh", "/api/auth/refresh",
  "/auth/logout", "/api/auth/logout",
]);
export const SESSION_EXPIRED_MESSAGE = "Your session expired. Sign in again to continue.";

export const isBackendConfigured = Boolean(API_BASE_URL) && !FORCE_SAMPLE_MODE;

/** A bounded transport error safe for presentation by feature adapters. */
export class ApiRequestError extends Error {
  constructor(message, { payload = null, status = 0 } = {}) {
    super(message);
    this.name = "ApiRequestError";
    this.payload = payload;
    this.status = status;
  }
}

// In-memory-only JWT access token. Deliberately never persisted to
// localStorage/sessionStorage: it lives only for the life of the tab, which
// bounds what an XSS exploit could exfiltrate. A page reload re-derives it
// from the HttpOnly refresh cookie via authClient.refresh().
let accessToken = null;

export function getAccessToken() {
  return accessToken;
}

export function setAccessToken(token) {
  accessToken = token || null;
}

// Registered once by authClient.js at module load, so apiClient.js can
// trigger a refresh attempt on a stale access token without importing
// authClient.js directly (that would be circular: authClient imports apiClient).
let unauthorizedRefreshHandler = null;

export function setUnauthorizedRefreshHandler(handler) {
  unauthorizedRefreshHandler = typeof handler === "function" ? handler : null;
}

export function shouldBroadcastUnauthorized(path, status, enabled = true) {
  const pathname = String(path || "").split("?", 1)[0];
  return enabled && status === 401 && !LOGIN_PATHS.has(pathname);
}

function readCookie(name) {
  if (typeof document === "undefined") return "";
  const prefix = `${encodeURIComponent(name)}=`;
  const entry = document.cookie
    .split(";")
    .map((part) => part.trim())
    .find((part) => part.startsWith(prefix));
  return entry ? decodeURIComponent(entry.slice(prefix.length)) : "";
}

function broadcastUnauthorized(path) {
  if (typeof window === "undefined") return;
  const detail = Object.freeze({ path: String(path || ""), reason: "expired" });
  const event = typeof window.CustomEvent === "function"
    ? new window.CustomEvent("cybershield:unauthorized", { detail })
    : new Event("cybershield:unauthorized");
  window.dispatchEvent(event);
}

function defaultFailureMessage(status) {
  if (status === 401) return SESSION_EXPIRED_MESSAGE;
  if (status === 403) return "Your account does not have permission for this action.";
  if (status >= 500) return "The service is temporarily unavailable. Try again shortly.";
  return `The service could not complete the request (${status}).`;
}

/**
 * Central browser API transport.
 *
 * Resource requests carry a short-lived JWT access token as an
 * `Authorization: Bearer` header (kept in memory only, never in a
 * JS-readable cookie or storage). The two remaining cookie-authenticated
 * endpoints — /auth/refresh and /auth/logout — still rely on the HttpOnly
 * refresh cookie and attach the non-secret double-submit CSRF value FastAPI
 * expects for them.
 */
export async function apiRequest(path, {
  broadcastUnauthorizedErrors = true,
  errorMessage = defaultFailureMessage,
  errorType: ErrorType = ApiRequestError,
  networkMessage = "The service is unreachable. Check the connection and try again.",
  timeoutMessage = "The request timed out. Please try again.",
  timeoutMs = REQUEST_TIMEOUT_MS,
  _isRetry = false,
  ...options
} = {}) {
  const controller = new AbortController();
  const timeoutId = globalThis.setTimeout(() => controller.abort(), timeoutMs);
  const method = String(options.method || "GET").toUpperCase();

  try {
    const headers = new Headers(options.headers);
    headers.set("Accept", "application/json");
    if (options.body && !(options.body instanceof FormData)) {
      headers.set("Content-Type", "application/json");
    }
    if (accessToken) {
      headers.set("Authorization", `Bearer ${accessToken}`);
    }
    if (!["GET", "HEAD"].includes(method)) {
      const csrfToken = readCookie(CSRF_COOKIE_NAME);
      if (csrfToken) headers.set("X-CSRF-Token", csrfToken);
    }

    const response = await fetch(`${API_BASE_URL}${path}`, {
      ...options,
      credentials: "include",
      headers,
      method,
      signal: controller.signal,
    });
    const payload = await response.json().catch(() => null);

    if (!response.ok) {
      const pathname = String(path || "").split("?", 1)[0];
      if (
        response.status === 401
        && !_isRetry
        && !NO_INTERCEPT_PATHS.has(pathname)
        && unauthorizedRefreshHandler
      ) {
        const refreshedUser = await unauthorizedRefreshHandler().catch(() => null);
        if (refreshedUser) {
          return apiRequest(path, {
            ...options,
            broadcastUnauthorizedErrors,
            errorMessage,
            errorType: ErrorType,
            networkMessage,
            timeoutMessage,
            timeoutMs,
            _isRetry: true,
          });
        }
      }

      if (shouldBroadcastUnauthorized(path, response.status, broadcastUnauthorizedErrors)) {
        broadcastUnauthorized(path);
      }
      throw new ErrorType(errorMessage(response.status, payload || {}), {
        payload,
        status: response.status,
      });
    }

    return payload;
  } catch (error) {
    if (error?.name === "AbortError") {
      throw new ErrorType(timeoutMessage, { status: 0 });
    }
    if (error instanceof ApiRequestError) throw error;
    if (error instanceof TypeError) {
      throw new ErrorType(networkMessage, { status: 0 });
    }
    throw error;
  } finally {
    globalThis.clearTimeout(timeoutId);
  }
}
