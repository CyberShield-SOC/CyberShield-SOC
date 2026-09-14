import {
  apiRequest,
  ApiRequestError,
  isBackendConfigured,
  setAccessToken,
  setUnauthorizedRefreshHandler,
} from "./apiClient.js";

export { isBackendConfigured };

export class AuthRequestError extends ApiRequestError {
  constructor(message, options = {}) {
    super(message, options);
    this.name = "AuthRequestError";
  }
}

export function getAuthFailureMessage(status, payload = {}) {
  if (status === 401) {
    return "The username or password you entered is incorrect";
  }
  if (status === 429) {
    return "Too many sign-in attempts. Wait a moment and try again.";
  }
  // Covers /auth/login's "couldn't send your verification code" (502) and
  // any other backend-authored failure that isn't the credentials check
  // above — surface its own message instead of a one-size-fits-all string.
  if (typeof payload?.detail === "string" && payload.detail.trim()) {
    return payload.detail.trim();
  }
  return "The secure service could not complete the request. Please try again.";
}

/**
 * Unlike getAuthFailureMessage (which deliberately rewords a 401 for the
 * login form), the backend's own /auth/2fa/* messages are already the
 * user-friendly copy — "Invalid verification code. Please try again.",
 * "Your verification code has expired. Request a new code.", the resend
 * cooldown's "Please wait Ns…" — so this passes them through verbatim
 * instead of collapsing everything into one generic string.
 */
export function getTwoFactorFailureMessage(status, payload = {}) {
  if (typeof payload?.detail === "string" && payload.detail.trim()) {
    return payload.detail.trim();
  }
  if (status === 429) return "Please wait before requesting another code.";
  if (status === 401) return "Your verification code has expired. Request a new code.";
  return "The secure service could not complete the request. Please try again.";
}

function safeAuthValidationDetail(payload) {
  const detail = payload?.detail;
  if (typeof detail === "string") return detail.slice(0, 240);
  if (Array.isArray(detail)) {
    // FastAPI's default Pydantic validation-error shape: a list of
    // {msg: "Value error, <message>", ...}. Strip Pydantic's prefix so a
    // policy rejection (e.g. from backend/app/validation/passwords.py)
    // reads as a plain sentence instead of a generic fallback.
    const messages = detail
      .map((item) => String(item?.msg || "").replace(/^value error,\s*/i, "").trim())
      .filter(Boolean);
    if (messages.length) return messages.join(" ").slice(0, 240);
  }
  return "";
}

/** /auth/forgot-password never reveals account existence, but a genuine
 * service failure (rate limit, outage) still needs a message to show. */
export function getPasswordResetRequestFailureMessage(status, payload = {}) {
  const detail = safeAuthValidationDetail(payload);
  if (detail) return detail;
  if (status === 429) return "Too many requests. Wait a moment and try again.";
  return "The secure service could not complete the request. Please try again.";
}

export function getPasswordResetFailureMessage(status, payload = {}) {
  const detail = safeAuthValidationDetail(payload);
  if (detail) return detail;
  if (status === 400) return "This reset link is invalid or has expired.";
  return "The secure service could not complete the request. Please try again.";
}

export function readAuthUser(payload) {
  const user = payload?.user;
  const supportedRoles = new Set(["Admin", "Analyst", "Viewer"]);
  if (
    !user
    || !Number.isSafeInteger(Number(user.id))
    || Number(user.id) <= 0
    || typeof user.username !== "string"
    || !user.username.trim()
    || typeof user.email !== "string"
    || !user.email.trim()
    || user.is_active !== true
    || !supportedRoles.has(user.role)
  ) {
    throw new AuthRequestError("The secure service returned an invalid response. Please try again.");
  }
  return user;
}

async function authRequest(path, options = {}) {
  return apiRequest(path, {
    ...options,
    errorMessage: getAuthFailureMessage,
    errorType: AuthRequestError,
    networkMessage: "The secure service is unavailable. Confirm the backend is running and try again.",
    timeoutMessage: "The secure service took too long to respond. Please try again.",
  });
}

export const authClient = {
  /**
   * Verify credentials and start (never complete) a two-factor login. No
   * access token exists yet — only /auth/2fa/verify's success mints one.
   * Returns { requiresTwoFactor: true, email } where `email` is the
   * account's own (masked) address for display, not necessarily the raw
   * value the user typed into the sign-in form.
   */
  async login({ email, password, remember }) {
    const payload = await authRequest("/auth/login", {
      method: "POST",
      body: JSON.stringify({
        username: email,
        password,
        remember_me: Boolean(remember),
      }),
    });
    if (!payload?.requiresTwoFactor) {
      throw new AuthRequestError("The secure service returned an invalid response. Please try again.");
    }
    return { requiresTwoFactor: true, email: String(payload.email || "") };
  },

  /** Complete a pending login. Only on success does a real session exist. */
  async verifyTwoFactor(code) {
    const payload = await authRequest("/auth/2fa/verify", {
      method: "POST",
      body: JSON.stringify({ code }),
      errorMessage: getTwoFactorFailureMessage,
    });
    const user = readAuthUser(payload);
    // The JWT access token lives in memory only (never localStorage/
    // sessionStorage) and is attached to resource requests by apiClient.
    // The HttpOnly refresh cookie the backend also set is what lets a later
    // page reload silently mint a new one via refresh().
    setAccessToken(payload.access_token);
    return user;
  },

  /** Invalidate the current code and email a new one. Never mints a session. */
  async resendTwoFactor() {
    const payload = await authRequest("/auth/2fa/resend", {
      method: "POST",
      errorMessage: getTwoFactorFailureMessage,
    });
    return String(payload?.message || "A new verification code has been sent.");
  },

  async currentUser() {
    // A 401 here means there's no current access token, which is normal on
    // a first visit. Only later protected requests should announce expiration.
    const payload = await authRequest("/auth/me", { broadcastUnauthorizedErrors: false });
    return readAuthUser(payload);
  },

  /**
   * Mint a new access token from the HttpOnly refresh cookie, if any. Used
   * both to resume a session on page load and as the automatic retry
   * apiClient triggers when a resource request's access token has expired
   * mid-session. Never throws — a failed refresh just means "not signed in"
   * or "session actually expired," which callers treat as a null user
   * rather than an error. A raw 401 from this call is never itself
   * broadcast as "your session expired" — that concept only applies to the
   * resource request that triggered the refresh attempt, which broadcasts
   * through its own normal path if the retry still fails.
   */
  async refresh() {
    try {
      const payload = await authRequest("/auth/refresh", {
        method: "POST",
        broadcastUnauthorizedErrors: false,
      });
      const user = readAuthUser(payload);
      setAccessToken(payload.access_token);
      return user;
    } catch {
      setAccessToken(null);
      return null;
    }
  },

  async logout() {
    try {
      await authRequest("/auth/logout", { method: "POST" });
    } finally {
      setAccessToken(null);
    }
  },

  /**
   * Start a password-reset challenge for `email`, if an account matches.
   * The response is identical whether or not it does — never branch UI
   * on it beyond showing the confirmation message.
   */
  async requestPasswordReset(email) {
    const payload = await authRequest("/auth/forgot-password", {
      method: "POST",
      body: JSON.stringify({ email }),
      errorMessage: getPasswordResetRequestFailureMessage,
    });
    return String(payload?.message || "");
  },

  /** Complete a reset with the token from the emailed link. */
  async resetPassword({ token, newPassword }) {
    const payload = await authRequest("/auth/reset-password", {
      method: "POST",
      body: JSON.stringify({ token, new_password: newPassword }),
      errorMessage: getPasswordResetFailureMessage,
    });
    return String(payload?.message || "");
  },
};

setUnauthorizedRefreshHandler(() => authClient.refresh());
