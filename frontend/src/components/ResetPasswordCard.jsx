import { useRef, useState } from "react";
import { ArrowRight, CircleCheck, KeyRound, ShieldAlert } from "lucide-react";
import { authClient, isBackendConfigured } from "../services/authClient";
import {
  PasswordMatchStatus,
  PasswordRequirementsChecklist,
} from "../soc/components/PasswordField";
import { isPasswordPolicyMet, passwordsMatch } from "../soc/utils/passwordPolicy";
import { AuthBackButton, AuthCardIntro } from "./AuthCardIntro";
import { FormField } from "./FormField";

function readResetTokenFromLocation() {
  if (typeof window === "undefined") return "";
  const hash = window.location.hash || "";
  const queryIndex = hash.indexOf("?");
  if (queryIndex === -1) return "";
  return new URLSearchParams(hash.slice(queryIndex + 1)).get("token") || "";
}

export function ResetPasswordCard({ onBack, onComplete }) {
  const [token] = useState(readResetTokenFromLocation);
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [requestError, setRequestError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [isDone, setIsDone] = useState(false);
  const passwordInput = useRef(null);

  const isReady = isPasswordPolicyMet(password) && passwordsMatch(password, confirmPassword);

  async function submitReset(event) {
    event.preventDefault();
    if (submitting || !isReady) return;

    setSubmitting(true);
    setRequestError("");
    try {
      await authClient.resetPassword({ token, newPassword: password });
      setIsDone(true);
    } catch (error) {
      setRequestError(error.message || "The password could not be reset. Please try again.");
    } finally {
      setSubmitting(false);
    }
  }

  if (!isBackendConfigured) {
    return (
      <section className="auth-card" aria-labelledby="reset-unavailable-title">
        <AuthBackButton onClick={onBack} />
        <AuthCardIntro
          icon={ShieldAlert}
          kicker="Account recovery"
          title="Not available in this mode"
          titleId="reset-unavailable-title"
        >
          Password reset requires a connected backend. Sign in to the sample workspace instead.
        </AuthCardIntro>
        <button className="primary-button auth-primary-action" type="button" onClick={onBack}>
          Return to sign in <ArrowRight size={17} aria-hidden="true" />
        </button>
      </section>
    );
  }

  if (!token) {
    return (
      <section className="auth-card" aria-labelledby="reset-invalid-title">
        <AuthBackButton onClick={onBack} />
        <AuthCardIntro
          icon={ShieldAlert}
          kicker="Account recovery"
          title="This reset link is invalid"
          titleId="reset-invalid-title"
        >
          Open the link from your most recent recovery email, or request a new one.
        </AuthCardIntro>
        <button className="primary-button auth-primary-action" type="button" onClick={onBack}>
          Return to sign in <ArrowRight size={17} aria-hidden="true" />
        </button>
      </section>
    );
  }

  if (isDone) {
    return (
      <section className="auth-card" aria-labelledby="reset-done-title">
        <AuthCardIntro
          icon={CircleCheck}
          iconState="verified"
          kicker="Password updated"
          title="Your password has been reset"
          titleId="reset-done-title"
        >
          Every other session for this account has been signed out. Sign in with your new password.
        </AuthCardIntro>
        <button className="primary-button auth-primary-action" type="button" onClick={onComplete}>
          Continue to sign in <ArrowRight size={17} aria-hidden="true" />
        </button>
      </section>
    );
  }

  return (
    <form
      className="auth-card"
      aria-labelledby="reset-title"
      noValidate
      onSubmit={submitReset}
    >
      <AuthBackButton onClick={onBack} />
      <AuthCardIntro
        icon={KeyRound}
        kicker="Account recovery"
        title="Set a new password"
        titleId="reset-title"
      >
        Choose a new password for your account.
      </AuthCardIntro>

      <div className="form-stack compact-stack">
        <div>
          <FormField
            id="reset-password"
            name="password"
            label="New password"
            icon={KeyRound}
            inputRef={passwordInput}
            type="password"
            value={password}
            onChange={(event) => {
              setPassword(event.target.value);
              if (requestError) setRequestError("");
            }}
            placeholder="Enter a new password"
            autoComplete="new-password"
            maxLength={256}
            required
          />
          <PasswordRequirementsChecklist password={password} />
        </div>

        <div>
          <FormField
            id="reset-confirm-password"
            name="confirmPassword"
            label="Confirm new password"
            icon={KeyRound}
            type="password"
            value={confirmPassword}
            onChange={(event) => {
              setConfirmPassword(event.target.value);
              if (requestError) setRequestError("");
            }}
            placeholder="Re-enter your new password"
            autoComplete="new-password"
            maxLength={256}
            required
          />
          <PasswordMatchStatus password={password} confirmPassword={confirmPassword} />
        </div>
      </div>

      {requestError && (
        <p className="field-error auth-request-error" role="alert">
          {requestError}
        </p>
      )}

      <button
        className="primary-button auth-primary-action"
        type="submit"
        disabled={submitting || !isReady}
      >
        {submitting ? "Updating…" : "Update password"} <ArrowRight size={17} aria-hidden="true" />
      </button>
    </form>
  );
}
