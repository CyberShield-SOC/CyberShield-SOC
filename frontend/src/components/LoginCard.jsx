import { useRef, useState } from "react";
import { ArrowRight, Fingerprint, KeyRound, LockKeyhole, Mail } from "lucide-react";
import { normalizeEmail, validateCredentials } from "../utils/authValidation";
import { AuthCardIntro } from "./AuthCardIntro";
import { FormField } from "./FormField";

export function LoginCard({ initialEmail, onContinue, onForgotPassword, onSso, sessionMessage = "" }) {
  const [email, setEmail] = useState(initialEmail);
  const [password, setPassword] = useState("");
  const [remember, setRemember] = useState(false);
  const [errors, setErrors] = useState({});
  const [requestError, setRequestError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const emailInput = useRef(null);
  const passwordInput = useRef(null);

  function clearError(field) {
    setErrors((current) => ({ ...current, [field]: undefined }));
  }

  async function submitCredentials(event) {
    event.preventDefault();
    if (submitting) return;

    const nextErrors = validateCredentials({ email, password });
    setErrors(nextErrors);
    setRequestError("");

    if (nextErrors.email) {
      emailInput.current?.focus();
      return;
    }
    if (nextErrors.password) {
      passwordInput.current?.focus();
      return;
    }

    setSubmitting(true);
    try {
      await onContinue({
        email: normalizeEmail(email),
        password,
        remember,
      });
    } catch (error) {
      setRequestError(error.message || "Sign-in could not be completed. Please try again.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form
      className="auth-card"
      aria-labelledby="login-title"
      noValidate
      onSubmit={submitCredentials}
    >
      <AuthCardIntro
        icon={LockKeyhole}
        kicker="Secure access"
        title="Welcome back"
        titleId="login-title"
      >
        Sign in to your SOC workspace.
      </AuthCardIntro>

      <div className="form-stack">
        <FormField
          id="login-email"
          name="email"
          label="Email"
          icon={Mail}
          inputRef={emailInput}
          type="email"
          value={email}
          onChange={(event) => {
            setEmail(event.target.value);
            if (errors.email) clearError("email");
            if (requestError) setRequestError("");
          }}
          placeholder="name@company.com"
          autoComplete="email"
          autoCapitalize="none"
          spellCheck="false"
          maxLength={254}
          required
          error={errors.email}
        />

        <div>
          <div className="field-heading-row">
            <label className="field-label" htmlFor="login-password">
              Password
            </label>
            <button className="text-link" type="button" onClick={onForgotPassword}>
              Forgot password?
            </button>
          </div>
          <FormField
            id="login-password"
            name="password"
            label=""
            icon={KeyRound}
            inputRef={passwordInput}
            type="password"
            value={password}
            onChange={(event) => {
              setPassword(event.target.value);
              if (errors.password) clearError("password");
              if (requestError) setRequestError("");
            }}
            placeholder="Enter your password"
            autoComplete="current-password"
            maxLength={256}
            required
            error={errors.password}
          />
        </div>
      </div>

      <label className="remember-row">
        <input
          name="remember"
          type="checkbox"
          checked={remember}
          onChange={(event) => setRemember(event.target.checked)}
        />
        <span>Remember me</span>
      </label>

      {sessionMessage && (
        <p className="auth-session-notice" role="status">
          {sessionMessage}
        </p>
      )}

      {requestError && (
        <p className="field-error auth-request-error" role="alert">
          {requestError}
        </p>
      )}

      <button className="primary-button auth-primary-action" type="submit" disabled={submitting}>
        {submitting ? "Signing in…" : "Sign in"} <ArrowRight size={17} aria-hidden="true" />
      </button>

      <div className="divider"><span>or</span></div>
      <button className="secondary-button" type="button" onClick={onSso}>
        <Fingerprint size={18} aria-hidden="true" /> Continue with UTA SSO
      </button>
      <p className="assurance-copy">
        Protected by adaptive authentication and device trust.
      </p>
    </form>
  );
}
