// Production builds default to the same-origin FastAPI contract. Developers
// can still set VITE_API_BASE_URL="" explicitly when they need sample mode.
const DEFAULT_API_BASE_URL = import.meta.env?.PROD ? "/api" : "";
const API_BASE_URL = String(import.meta.env?.VITE_API_BASE_URL ?? DEFAULT_API_BASE_URL).replace(/\/$/, "");
const FORCE_SAMPLE_MODE = String(import.meta.env?.VITE_USE_MOCK_DATA || "").toLowerCase() === "true";
const REQUEST_TIMEOUT_MS = 12_000;
const CSRF_COOKIE_NAME = "cybershield_csrf";
const LOGIN_PATHS = new Set(["/auth/login", "/api/auth/login"]);
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
 * Authentication is carried by the server-issued HttpOnly cookie, not by a
 * JavaScript-readable bearer token. Cookie-authenticated writes also attach
 * the non-secret double-submit CSRF value expected by FastAPI.
 */
export async function apiRequest(path, {
  broadcastUnauthorizedErrors = true,
  errorMessage = defaultFailureMessage,
  errorType: ErrorType = ApiRequestError,
  networkMessage = "The service is unreachable. Check the connection and try again.",
  timeoutMessage = "The request timed out. Please try again.",
  timeoutMs = REQUEST_TIMEOUT_MS,
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
