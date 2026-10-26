import { useEffect, useRef, useState } from "react";
import { ArrowRight, CircleAlert, Fingerprint } from "lucide-react";
import { isCompleteOtp, sanitizeOtp } from "../utils/authValidation";
import { AuthBackButton, AuthCardIntro } from "./AuthCardIntro";

const OTP_LENGTH = 6;
const RESEND_COOLDOWN_SECONDS = 60;

export function MfaCard({ email, onBack, onResend, onVerified }) {
  const [digits, setDigits] = useState(() => Array(OTP_LENGTH).fill(""));
  const [error, setError] = useState("");
  const [resendStatus, setResendStatus] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [resending, setResending] = useState(false);
  const [cooldown, setCooldown] = useState(RESEND_COOLDOWN_SECONDS);
  const [resendAvailableAt, setResendAvailableAt] = useState(() => Date.now() + RESEND_COOLDOWN_SECONDS * 1000);
  const inputs = useRef([]);

  // The backend starts its own resend cooldown the moment the first code is
  // sent (at login), so the timer here starts immediately too rather than
  // waiting for a first "Resend" click.
  useEffect(() => {
    const remaining = () => Math.max(0, Math.ceil((resendAvailableAt - Date.now()) / 1000));
    setCooldown(remaining());
    if (remaining() === 0) return undefined;
    const intervalId = window.setInterval(() => {
      const seconds = remaining();
      setCooldown(seconds);
      if (seconds === 0) window.clearInterval(intervalId);
    }, 1000);
    return () => window.clearInterval(intervalId);
  }, [resendAvailableAt]);

  function updateDigits(startIndex, value) {
    if (sanitizeOtp(value).length === OTP_LENGTH) startIndex = 0;
    const incomingDigits = sanitizeOtp(value).slice(0, OTP_LENGTH - startIndex);
    if (!incomingDigits) return;

    setDigits((current) => {
      const next = [...current];
      incomingDigits.split("").forEach((digit, offset) => {
        next[startIndex + offset] = digit;
      });
      return next;
    });
    setError("");

    const nextIndex = Math.min(startIndex + incomingDigits.length, OTP_LENGTH - 1);
    inputs.current[nextIndex]?.focus();
  }

  async function submitCode(event) {
    event.preventDefault();
    if (submitting || resending) return;

    if (!isCompleteOtp(digits)) {
      setError("Enter the complete six-digit verification code.");
      const firstEmptyIndex = digits.findIndex((digit) => !digit);
      inputs.current[Math.max(firstEmptyIndex, 0)]?.focus();
      return;
    }

    setError("");
    setSubmitting(true);
    try {
      await onVerified(digits.join(""));
    } catch (verifyError) {
      setError(verifyError.message || "The verification code could not be checked. Please try again.");
      setDigits(Array(OTP_LENGTH).fill(""));
      inputs.current[0]?.focus();
    } finally {
      setSubmitting(false);
    }
  }

  async function submitResend() {
    if (submitting || resending || cooldown > 0) return;
    setResendStatus("");
    setError("");
    setResending(true);
    try {
      const message = await onResend();
      setResendStatus(message || "A new verification code has been sent.");
      setDigits(Array(OTP_LENGTH).fill(""));
      inputs.current[0]?.focus();
      setCooldown(RESEND_COOLDOWN_SECONDS);
      setResendAvailableAt(Date.now() + RESEND_COOLDOWN_SECONDS * 1000);
    } catch (resendError) {
      setError(resendError.message || "The verification code could not be resent. Please try again.");
    } finally {
      setResending(false);
    }
  }

  return (
    <form
      className="auth-card"
      aria-labelledby="mfa-title"
      noValidate
      onSubmit={submitCode}
    >
      <AuthBackButton onClick={onBack} disabled={submitting || resending} />
      <AuthCardIntro
        icon={Fingerprint}
        kicker="Additional verification"
        title="Two-factor authentication"
        titleId="mfa-title"
      >
        Enter the six-digit verification code for <strong>{email || "your email"}</strong>.
      </AuthCardIntro>

      <div
        className={`otp-grid ${error ? "has-error" : ""}`}
        role="group"
        aria-label="Six-digit verification code"
        aria-describedby={error ? "otp-error" : undefined}
      >
        {digits.map((digit, index) => (
          <input
            key={index}
            ref={(node) => { inputs.current[index] = node; }}
            id={`otp-${index + 1}`}
            name={`otp-${index + 1}`}
            type="text"
            aria-label={`Verification digit ${index + 1}`}
            aria-invalid={Boolean(error)}
            autoComplete={index === 0 ? "one-time-code" : "off"}
            inputMode="numeric"
            pattern="[0-9]*"
            maxLength={index === 0 ? OTP_LENGTH : 1}
            value={digit}
            required
            disabled={submitting || resending}
            onPaste={(event) => {
              event.preventDefault();
              updateDigits(index, event.clipboardData.getData("text"));
            }}
            onChange={(event) => {
              if (sanitizeOtp(event.target.value).length > 1) {
                updateDigits(index, event.target.value);
                return;
              }
              const nextDigit = sanitizeOtp(event.target.value).slice(-1);
              setDigits((current) => current.map((item, itemIndex) => (
                itemIndex === index ? nextDigit : item
              )));
              if (error) setError("");
              if (nextDigit && index < OTP_LENGTH - 1) {
                inputs.current[index + 1]?.focus();
              }
            }}
            onKeyDown={(event) => {
              if (event.key === "Backspace" && !digit && index > 0) {
                inputs.current[index - 1]?.focus();
              }
              if (event.key === "ArrowLeft" && index > 0) {
                event.preventDefault();
                inputs.current[index - 1]?.focus();
              }
              if (event.key === "ArrowRight" && index < OTP_LENGTH - 1) {
                event.preventDefault();
                inputs.current[index + 1]?.focus();
              }
            }}
          />
        ))}
      </div>

      {error && (
        <p className="field-error" id="otp-error" role="alert">
          <CircleAlert size={14} aria-hidden="true" /> {error}
        </p>
      )}

      <button className="primary-button auth-primary-action" type="submit" disabled={submitting || resending}>
        {submitting ? "Verifying…" : "Verify identity"} <ArrowRight size={17} aria-hidden="true" />
      </button>
      <div className="mfa-footer">
        <span>Didn&apos;t receive a code?</span>
        <button
          className="text-link"
          type="button"
          disabled={submitting || resending || cooldown > 0}
          onClick={submitResend}
        >
          {resending ? "Sending…" : cooldown > 0 ? `Resend code (${cooldown}s)` : "Resend code"}
        </button>
      </div>
      {resendStatus && (
        <p className="inline-status" role="status" aria-live="polite">
          {resendStatus}
        </p>
      )}
    </form>
  );
}
