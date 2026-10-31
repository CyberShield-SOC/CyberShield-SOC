import { useEffect, useRef, useState } from "react";
import { ArrowRight, CircleCheck, KeyRound, ShieldAlert, ShieldCheck, UserPlus } from "lucide-react";
import { authClient, isBackendConfigured } from "../services/authClient";
import {
  PasswordMatchStatus,
  PasswordRequirementsChecklist,
} from "../soc/components/PasswordField";
import { isPasswordPolicyMet, passwordsMatch } from "../soc/utils/passwordPolicy";
import { readTokenFromLocation } from "../utils/authValidation";
import { AuthBackButton, AuthCardIntro } from "./AuthCardIntro";
import { FormField } from "./FormField";

function validateUsername(value) {
  const normalized = String(value || "").trim();
  if (normalized.length < 3) return "Username must be at least 3 characters.";
  if (normalized.length > 50) return "Username must be 50 characters or fewer.";
  return "";
}

export function AcceptInviteCard({ onBack, onComplete }) {
  const [token] = useState(readTokenFromLocation);
  const [invite, setInvite] = useState(null);
  const [loadError, setLoadError] = useState("");
  const [loading, setLoading] = useState(true);
  const [fullName, setFullName] = useState("");
  const [username, setUsername] = useState("");
  const [usernameError, setUsernameError] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [requestError, setRequestError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [isDone, setIsDone] = useState(false);
  const usernameInput = useRef(null);

  useEffect(() => {
    if (!token || !isBackendConfigured) {
      setLoading(false);
      return;
    }
    let cancelled = false;
    authClient.getInviteDetails(token)
      .then((details) => {
        if (!cancelled) setInvite(details);
      })
      .catch((error) => {
        if (!cancelled) setLoadError(error.message || "This invite link is invalid or has expired.");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => { cancelled = true; };
  }, [token]);

  const isReady = (
    !validateUsername(username)
    && isPasswordPolicyMet(password)
    && passwordsMatch(password, confirmPassword)
  );

  async function submitAccept(event) {
    event.preventDefault();
    const nextUsernameError = validateUsername(username);
    setUsernameError(nextUsernameError);
    if (nextUsernameError) {
      usernameInput.current?.focus();
      return;
    }
    if (submitting || !isReady) return;

    setSubmitting(true);
    setRequestError("");
    try {
      await authClient.acceptInvite({ token, username: username.trim(), fullName, password });
      setIsDone(true);
    } catch (error) {
      setRequestError(error.message || "The account could not be created. Please try again.");
    } finally {
      setSubmitting(false);
    }
  }

  if (!isBackendConfigured) {
    return (
      <section className="auth-card" aria-labelledby="invite-unavailable-title">
        <AuthBackButton onClick={onBack} />
        <AuthCardIntro
          icon={ShieldAlert}
          kicker="Account invite"
          title="Not available in this mode"
          titleId="invite-unavailable-title"
        >
          Accepting an invite requires a connected backend. Sign in to the sample workspace instead.
        </AuthCardIntro>
        <button className="primary-button auth-primary-action" type="button" onClick={onBack}>
          Return to sign in <ArrowRight size={17} aria-hidden="true" />
        </button>
      </section>
    );
  }

  if (!token || loadError) {
    return (
      <section className="auth-card" aria-labelledby="invite-invalid-title">
        <AuthBackButton onClick={onBack} />
        <AuthCardIntro
          icon={ShieldAlert}
          kicker="Account invite"
          title="This invite link is invalid"
          titleId="invite-invalid-title"
        >
          {loadError || "Open the link from your most recent invite email, or ask your administrator to resend it."}
        </AuthCardIntro>
        <button className="primary-button auth-primary-action" type="button" onClick={onBack}>
          Return to sign in <ArrowRight size={17} aria-hidden="true" />
        </button>
      </section>
    );
  }

  if (loading) {
    return (
      <section className="auth-card" aria-labelledby="invite-loading-title">
        <AuthCardIntro
          icon={UserPlus}
          kicker="Account invite"
          title="Checking your invite…"
          titleId="invite-loading-title"
        >
          One moment while we confirm your invite link.
        </AuthCardIntro>
      </section>
    );
  }

  if (isDone) {
    return (
      <section className="auth-card" aria-labelledby="invite-done-title">
        <AuthCardIntro
          icon={CircleCheck}
          iconState="verified"
          kicker="Account created"
          title="Your account is ready"
          titleId="invite-done-title"
        >
          Sign in with the username and password you just chose.
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
      aria-labelledby="invite-title"
      noValidate
      onSubmit={submitAccept}
    >
      <AuthBackButton onClick={onBack} disabled={submitting} />
      <AuthCardIntro
        icon={UserPlus}
        kicker="Account invite"
        title="Complete your account"
        titleId="invite-title"
      >
        You&rsquo;ve been invited to join CyberShield SOC as a {invite?.role || "member"}.
      </AuthCardIntro>

      <div className="organization-card">
        <span className="organization-icon" aria-hidden="true">
          <ShieldCheck size={21} />
        </span>
        <span>
          <strong>{invite?.email}</strong>
          <small>Invited as {invite?.role}</small>
        </span>
      </div>

      <div className="form-stack compact-stack">
        <FormField
          id="invite-full-name"
          name="fullName"
          label="Full name"
          icon={UserPlus}
          disabled={submitting}
          type="text"
          value={fullName}
          onChange={(event) => setFullName(event.target.value)}
          placeholder="Jordan Avery"
          autoComplete="name"
          maxLength={100}
        />

        <FormField
          id="invite-username"
          name="username"
          label="Username"
          icon={UserPlus}
          inputRef={usernameInput}
          disabled={submitting}
          type="text"
          value={username}
          onChange={(event) => {
            setUsername(event.target.value);
            if (usernameError) setUsernameError("");
            if (requestError) setRequestError("");
          }}
          placeholder="Choose a username"
          autoComplete="username"
          autoCapitalize="none"
          spellCheck="false"
          maxLength={50}
          required
          error={usernameError}
        />

        <div>
          <FormField
            id="invite-password"
            name="password"
            label="Password"
            icon={KeyRound}
            disabled={submitting}
            type="password"
            value={password}
            onChange={(event) => {
              setPassword(event.target.value);
              if (requestError) setRequestError("");
            }}
            placeholder="Choose a password"
            autoComplete="new-password"
            maxLength={256}
            required
          />
          <PasswordRequirementsChecklist password={password} />
        </div>

        <div>
          <FormField
            id="invite-confirm-password"
            disabled={submitting}
            name="confirmPassword"
            label="Confirm password"
            icon={KeyRound}
            type="password"
            value={confirmPassword}
            onChange={(event) => {
              setConfirmPassword(event.target.value);
              if (requestError) setRequestError("");
            }}
            placeholder="Re-enter your password"
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
        {submitting ? "Creating account…" : "Create account"} <ArrowRight size={17} aria-hidden="true" />
      </button>
    </form>
  );
}
