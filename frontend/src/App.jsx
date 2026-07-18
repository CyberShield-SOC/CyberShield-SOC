import { lazy, Suspense, useEffect, useState } from "react";
import { Moon, Sun } from "lucide-react";
import { BrandMark, BrandPanel } from "./components/BrandPanel";
import { LoginCard } from "./components/LoginCard";
import { LogoutSuccessCard } from "./components/LogoutSuccessCard";
import { MfaCard } from "./components/MfaCard";
import { RecoveryCard } from "./components/RecoveryCard";
import { SsoCard } from "./components/SsoCard";
import { SupportCard } from "./components/SupportCard";
import {
  AUTH_ROUTES,
  isSocRoute,
  shouldRejectUninitiatedMfa,
  shouldRedirectAuthenticatedLogin,
  SOC_ROUTES,
  useAuthRoute,
} from "./hooks/useAuthRoute";
import { useTheme } from "./hooks/useTheme";
import { useSession } from "./hooks/useSession";
import { SESSION_EXPIRED_MESSAGE } from "./services/apiClient";

const SocApp = lazy(() => import("./soc/SocApp"));

const DEMO_EMAIL = "admin@cybershield.io";

export default function App() {
  const { route, navigate } = useAuthRoute();
  const { theme, toggleTheme } = useTheme();
  const {
    mode: sessionMode,
    status: sessionStatus,
    sessionActive,
    sessionExpired,
    expiresAt,
    user,
    signIn,
    beginDemoSession,
    signOut,
  } = useSession();
  const [email, setEmail] = useState(DEMO_EMAIL);
  const [authNotice, setAuthNotice] = useState("");
  const [mfaPending, setMfaPending] = useState(false);
  const [intendedRoute, setIntendedRoute] = useState(() => (
    isSocRoute(route) ? route : SOC_ROUTES.dashboard
  ));
  const isDarkTheme = theme === "dark";

  useEffect(() => {
    if (sessionExpired) setAuthNotice(SESSION_EXPIRED_MESSAGE);
  }, [sessionExpired]);

  useEffect(() => {
    if (isSocRoute(route) && mfaPending) {
      setIntendedRoute(route);
      navigate(AUTH_ROUTES.mfa);
      return;
    }
    if (isSocRoute(route) && sessionStatus === "anonymous") {
      setIntendedRoute(route);
      navigate(AUTH_ROUTES.login);
    }
  }, [mfaPending, navigate, route, sessionStatus]);

  useEffect(() => {
    if (shouldRedirectAuthenticatedLogin(route, sessionStatus)) {
      navigate(SOC_ROUTES.dashboard);
    }
  }, [navigate, route, sessionStatus]);

  useEffect(() => {
    if (shouldRejectUninitiatedMfa(route, sessionStatus, mfaPending)) {
      navigate(AUTH_ROUTES.login);
    }
  }, [mfaPending, navigate, route, sessionStatus]);

  if (isSocRoute(route)) {
    if (!sessionActive) {
      return <div className="app-loading">Verifying your workspace session…</div>;
    }
    return (
      <Suspense fallback={<div className="app-loading">Opening your SOC workspace…</div>}>
        <SocApp
          route={route}
          navigate={navigate}
          theme={theme}
          toggleTheme={toggleTheme}
          expiresAt={expiresAt}
          user={user}
          onSignOut={async () => {
            await signOut();
            navigate(AUTH_ROUTES.logoutSuccess);
          }}
        />
      </Suspense>
    );
  }

  function showMfa(nextEmail) {
    setEmail(nextEmail);
    setMfaPending(true);
    navigate(AUTH_ROUTES.mfa);
  }

  async function submitCredentials(credentials) {
    setEmail(credentials.email);
    setAuthNotice("");
    if (sessionMode === "api") {
      // The current API validates the primary credentials but does not yet
      // expose an MFA challenge endpoint. Keep the MFA screen in the flow so
      // the UI is ready for that contract without treating it as a server-side
      // security boundary.
      await signIn(credentials);
    }
    showMfa(credentials.email);
  }

  async function returnFromMfa() {
    // Connected login currently creates the server session before the visual
    // MFA step. Revoke that provisional session when the user goes back.
    if (sessionMode === "api") await signOut();
    setMfaPending(false);
    navigate(AUTH_ROUTES.login);
  }

  function completeMfa() {
    if (!mfaPending && sessionStatus !== "authenticated") {
      navigate(AUTH_ROUTES.login);
      return;
    }
    if (sessionMode === "demo") beginDemoSession();
    setMfaPending(false);
    navigate(intendedRoute);
  }

  function renderAuthView() {
    switch (route) {
      case AUTH_ROUTES.mfa:
        return (
          <MfaCard
            email={email}
            onBack={returnFromMfa}
            onVerified={completeMfa}
          />
        );
      case AUTH_ROUTES.logoutSuccess:
        return <LogoutSuccessCard onReturn={() => navigate(AUTH_ROUTES.login)} />;
      case AUTH_ROUTES.forgotPassword:
        return (
          <RecoveryCard
            initialEmail={email}
            onBack={() => navigate(AUTH_ROUTES.login)}
          />
        );
      case AUTH_ROUTES.sso:
        return <SsoCard onBack={() => navigate(AUTH_ROUTES.login)} />;
      case AUTH_ROUTES.support:
        return <SupportCard onBack={() => navigate(AUTH_ROUTES.login)} />;
      default:
        return (
          <LoginCard
            initialEmail={DEMO_EMAIL}
            sessionMessage={authNotice}
            onContinue={submitCredentials}
            onForgotPassword={() => navigate(AUTH_ROUTES.forgotPassword)}
            onSso={() => navigate(AUTH_ROUTES.sso)}
          />
        );
    }
  }

  return (
    <main className="app-shell" data-theme={theme} data-route={route}>
      <section className="auth-panel" aria-label="CyberShield authentication">
        <button
          className="theme-toggle"
          type="button"
          onClick={toggleTheme}
          aria-label={`Switch to ${isDarkTheme ? "light" : "dark"} theme`}
          aria-pressed={!isDarkTheme}
        >
          {isDarkTheme ? <Sun size={18} /> : <Moon size={18} />}
        </button>

        <div className="auth-wrap">
          <div className="mobile-brand">
            <BrandMark adaptive />
          </div>

          <div className="auth-view" key={route}>
            {renderAuthView()}
          </div>

          {route !== AUTH_ROUTES.support && (
            <p className="support-copy">
              Need help?{" "}
              <button type="button" onClick={() => navigate(AUTH_ROUTES.support)}>
                Contact security support
              </button>
            </p>
          )}
        </div>
      </section>

      <BrandPanel />
    </main>
  );
}
