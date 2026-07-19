import { useCallback, useEffect, useState } from "react";

const SESSION_KEY = "cybershield-demo-session";
const SESSION_DURATION_MS = 30 * 60 * 1000;

function readSession() {
  try {
    const parsed = JSON.parse(window.sessionStorage.getItem(SESSION_KEY));
    const expiresAt = Number(parsed?.expiresAt);
    const remaining = expiresAt - Date.now();
    if (Number.isFinite(expiresAt) && remaining > 0 && remaining <= SESSION_DURATION_MS) {
      return { expiresAt };
    }
    window.sessionStorage.removeItem(SESSION_KEY);
  } catch {
    // A restricted browser context behaves as a signed-out session.
  }
  return null;
}

export function useDemoSession() {
  const [session, setSession] = useState(readSession);

  const beginSession = useCallback(() => {
    const next = { expiresAt: Date.now() + SESSION_DURATION_MS };
    setSession(next);
    try {
      window.sessionStorage.setItem(SESSION_KEY, JSON.stringify(next));
    } catch {
      // The in-memory session still supports the current tab.
    }
  }, []);

  const endSession = useCallback(() => {
    setSession(null);
    try {
      window.sessionStorage.removeItem(SESSION_KEY);
    } catch {
      // Nothing else is required when session storage is unavailable.
    }
  }, []);

  useEffect(() => {
    if (!session) return undefined;
    const timeout = window.setTimeout(() => endSession(), Math.max(session.expiresAt - Date.now(), 0));
    return () => window.clearTimeout(timeout);
  }, [endSession, session]);

  return {
    sessionActive: Boolean(session && session.expiresAt > Date.now()),
    expiresAt: session?.expiresAt || null,
    beginSession,
    endSession,
  };
}
