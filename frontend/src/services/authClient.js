import {
  apiRequest,
  ApiRequestError,
  isBackendConfigured,
} from "./apiClient.js";

export { isBackendConfigured };

export class AuthRequestError extends ApiRequestError {
  constructor(message, options = {}) {
    super(message, options);
    this.name = "AuthRequestError";
  }
}

export function getAuthFailureMessage(status) {
  if (status === 401) {
    return "The username or password you entered is incorrect";
  }
  if (status === 429) {
    return "Too many sign-in attempts. Wait a moment and try again.";
  }
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
  async login({ email, password, remember }) {
    const payload = await authRequest("/auth/login", {
      method: "POST",
      body: JSON.stringify({
        username: email,
        password,
        remember_me: Boolean(remember),
      }),
    });
    // The backend also returns the opaque token for non-browser API clients.
    // The web app deliberately discards it and relies on the HttpOnly cookie.
    return readAuthUser(payload);
  },

  async currentUser() {
    // A 401 here means the browser has no current session, which is normal on
    // a first visit. Only later protected requests should announce expiration.
    const payload = await authRequest("/auth/me", { broadcastUnauthorizedErrors: false });
    return readAuthUser(payload);
  },

  async logout() {
    await authRequest("/auth/logout", { method: "POST" });
  },
};
