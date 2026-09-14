import { lazy, Suspense, useEffect, useState } from "react";
import { Moon, Sun } from "lucide-react";
import { BrandMark, BrandPanel } from "./components/BrandPanel";
import { LoginCard } from "./components/LoginCard";
import { LogoutSuccessCard } from "./components/LogoutSuccessCard";
import { MfaCard } from "./components/MfaCard";
import { RecoveryCard } from "./components/RecoveryCard";
import { ResetPasswordCard } from "./components/ResetPasswordCard";
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
    completeTwoFactor,
    resendTwoFactorCode,
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
    setAuthNotice("");
    if (sessionMode === "api") {
      // signIn() only verifies credentials and starts the email OTP step —
      // no session exists yet. The account's own (masked) email comes back
      // from the server rather than trusting whatever the user typed.
      const pending = await signIn(credentials);
      showMfa(pending?.email || credentials.email);
      return;
    }
    showMfa(credentials.email);
  }

  async function returnFromMfa() {
    // api mode never created a session at the credentials step (only a
    // pending-verification cookie the backend already scopes to 2FA), so
    // there is nothing to revoke here — going back just returns to sign-in.
    setMfaPending(false);
    navigate(AUTH_ROUTES.login);
  }

  async function verifyMfaCode(code) {
    if (sessionMode === "api") {
      // Throws with a friendly message on a wrong/expired/locked-out code;
      // MfaCard displays it. Only on success does a real session exist.
      await completeTwoFactor(code);
    } else {
      beginDemoSession();
    }
    setMfaPending(false);
    navigate(intendedRoute);
  }

  async function resendMfaCode() {
    if (sessionMode === "api") return resendTwoFactorCode();
    return "A new verification code has been sent.";
  }

  function renderAuthView() {
    switch (route) {
      case AUTH_ROUTES.mfa:
        return (
          <MfaCard
            email={email}
            onBack={returnFromMfa}
            onVerified={verifyMfaCode}
            onResend={resendMfaCode}
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
      case AUTH_ROUTES.resetPassword:
        return (
          <ResetPasswordCard
            onBack={() => navigate(AUTH_ROUTES.login)}
            onComplete={() => navigate(AUTH_ROUTES.login)}
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
