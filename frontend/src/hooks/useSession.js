import { useCallback, useEffect, useRef, useState } from "react";
import { authClient, isBackendConfigured } from "../services/authClient";
import { useDemoSession } from "./useDemoSession";

export function useSession() {
  const demo = useDemoSession();
  const [serverSession, setServerSession] = useState({
    status: isBackendConfigured ? "checking" : "anonymous",
    user: null,
    expired: false,
  });
  const sessionVersionRef = useRef(0);

  useEffect(() => {
    if (!isBackendConfigured) return undefined;
    let active = true;
    const requestVersion = ++sessionVersionRef.current;

    // Resume the session from the HttpOnly refresh cookie (if any) rather
    // than calling /auth/me directly: resource routes now require a Bearer
    // access token, which only exists in memory and doesn't survive a page
    // reload on its own.
    authClient.refresh()
      .then((user) => {
        if (active && sessionVersionRef.current === requestVersion) {
          setServerSession(
            user
              ? { status: "authenticated", user, expired: false }
              : { status: "anonymous", user: null, expired: false },
          );
        }
      });

    function handleUnauthorized() {
      sessionVersionRef.current += 1;
      // This event comes only from protected API requests. Keep the message
      // separate from an ordinary first visit to the sign-in page.
      setServerSession({ status: "anonymous", user: null, expired: true });
    }
    window.addEventListener("cybershield:unauthorized", handleUnauthorized);
    return () => {
      active = false;
      window.removeEventListener("cybershield:unauthorized", handleUnauthorized);
    };
  }, []);

  // Verifies credentials and starts the two-factor step. Deliberately does
  // NOT set serverSession to "authenticated" — no session exists until
  // completeTwoFactor() succeeds. Returns { requiresTwoFactor, email }.
  const signIn = useCallback(async (credentials) => {
    if (!isBackendConfigured) return null;
    return authClient.login(credentials);
  }, []);

  const completeTwoFactor = useCallback(async (code) => {
    if (!isBackendConfigured) return null;
    sessionVersionRef.current += 1;
    const user = await authClient.verifyTwoFactor(code);
    setServerSession({ status: "authenticated", user, expired: false });
    return user;
  }, []);

  const resendTwoFactorCode = useCallback(async () => {
    if (!isBackendConfigured) return "";
    return authClient.resendTwoFactor();
  }, []);

  const beginDemoSession = useCallback(() => {
    demo.beginSession();
  }, [demo]);

  const signOut = useCallback(async () => {
    if (isBackendConfigured) {
      sessionVersionRef.current += 1;
      try {
        await authClient.logout();
      } catch {
        // A missing/expired server session is still signed out locally.
      } finally {
        setServerSession({ status: "anonymous", user: null, expired: false });
      }
      return;
    }
    demo.endSession();
  }, [demo]);

  if (!isBackendConfigured) {
    return {
      mode: "demo",
      status: demo.sessionActive ? "authenticated" : "anonymous",
      sessionActive: demo.sessionActive,
      expiresAt: demo.expiresAt,
      user: null,
      signIn,
      completeTwoFactor,
      resendTwoFactorCode,
      beginDemoSession,
      signOut,
    };
  }

  return {
    mode: "api",
    status: serverSession.status,
    sessionActive: serverSession.status === "authenticated",
    sessionExpired: serverSession.expired,
    expiresAt: null,
    user: serverSession.user,
    signIn,
    completeTwoFactor,
    resendTwoFactorCode,
    beginDemoSession,
    signOut,
  };
}
