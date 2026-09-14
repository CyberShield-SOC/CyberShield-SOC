import { useRef, useState } from "react";
import { ArrowRight, Mail, MailCheck } from "lucide-react";
import { authClient, isBackendConfigured } from "../services/authClient";
import { normalizeEmail, validateEmail } from "../utils/authValidation";
import { AuthBackButton, AuthCardIntro } from "./AuthCardIntro";
import { FormField } from "./FormField";

export function RecoveryCard({ initialEmail, onBack }) {
  const [email, setEmail] = useState(initialEmail);
  const [error, setError] = useState("");
  const [requestError, setRequestError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [isReady, setIsReady] = useState(false);
  const emailInput = useRef(null);

  async function submitRecovery(event) {
    event.preventDefault();
    if (submitting) return;

    const nextError = validateEmail(email);
    setError(nextError);
    setRequestError("");

    if (nextError) {
      emailInput.current?.focus();
      return;
    }

    const normalized = normalizeEmail(email);
    setEmail(normalized);

    if (!isBackendConfigured) {
      setIsReady(true);
      return;
    }

    setSubmitting(true);
    try {
      // The backend's response never reveals whether the email matched an
      // account — a thrown error here means the request itself failed
      // (network, rate limit), not that the address was unrecognized.
      await authClient.requestPasswordReset(normalized);
      setIsReady(true);
    } catch (requestErr) {
      setRequestError(requestErr.message || "The request could not be completed. Please try again.");
    } finally {
      setSubmitting(false);
    }
  }

  if (isReady) {
    return (
      <section className="auth-card" aria-labelledby="recovery-ready-title">
        <AuthBackButton onClick={onBack} />
        <AuthCardIntro
          icon={MailCheck}
          iconState="verified"
          kicker="Recovery requested"
          title="Check your inbox"
          titleId="recovery-ready-title"
        >
          If an account matches <strong>{email}</strong>, recovery instructions will be sent.
        </AuthCardIntro>

        <div className="info-panel">
          For your security, the confirmation is the same whether or not an account exists.
        </div>
        <button className="primary-button auth-primary-action" type="button" onClick={onBack}>
          Return to sign in <ArrowRight size={17} aria-hidden="true" />
        </button>
      </section>
    );
  }

  return (
    <form
      className="auth-card"
      aria-labelledby="recovery-title"
      noValidate
      onSubmit={submitRecovery}
    >
      <AuthBackButton onClick={onBack} />
      <AuthCardIntro
        icon={Mail}
        kicker="Account recovery"
        title="Reset your password"
        titleId="recovery-title"
      >
        Enter your email and we'll send recovery instructions if an account matches.
      </AuthCardIntro>

      <div className="form-stack compact-stack">
        <FormField
          id="recovery-email"
          name="recovery-email"
          label="Email"
          icon={Mail}
          inputRef={emailInput}
          type="email"
          value={email}
          onChange={(event) => {
            setEmail(event.target.value);
            if (error) setError("");
            if (requestError) setRequestError("");
          }}
          placeholder="name@company.com"
          autoComplete="email"
          autoCapitalize="none"
          spellCheck="false"
          maxLength={254}
          required
          error={error}
        />
      </div>

      {requestError && (
        <p className="field-error auth-request-error" role="alert">
          {requestError}
        </p>
      )}

      <button className="primary-button auth-primary-action" type="submit" disabled={submitting}>
        {submitting ? "Sending…" : "Continue recovery"} <ArrowRight size={17} aria-hidden="true" />
      </button>
      <p className="assurance-copy">
        Passwords and verification codes are never requested by email.
      </p>
    </form>
  );
}
