import { useRef, useState } from "react";
import { ArrowRight, CircleAlert, Fingerprint } from "lucide-react";
import { isCompleteOtp, sanitizeOtp } from "../utils/authValidation";
import { AuthBackButton, AuthCardIntro } from "./AuthCardIntro";

const OTP_LENGTH = 6;

export function MfaCard({ email, onBack, onVerified }) {
  const [digits, setDigits] = useState(() => Array(OTP_LENGTH).fill(""));
  const [error, setError] = useState("");
  const [resendStatus, setResendStatus] = useState("");
  const inputs = useRef([]);

  function updateDigits(startIndex, value) {
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

  function submitCode(event) {
    event.preventDefault();

    if (!isCompleteOtp(digits)) {
      setError("Enter the complete six-digit verification code.");
      const firstEmptyIndex = digits.findIndex((digit) => !digit);
      inputs.current[Math.max(firstEmptyIndex, 0)]?.focus();
      return;
    }

    // Frontend-only until the backend exposes challenge verification. The
    // server must become authoritative before this can enforce real MFA.
    onVerified();
  }

  return (
    <form
      className="auth-card"
      aria-labelledby="mfa-title"
      noValidate
      onSubmit={submitCode}
    >
      <AuthBackButton onClick={onBack} />
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
            maxLength={1}
            value={digit}
            required
            onPaste={(event) => {
              event.preventDefault();
              updateDigits(index, event.clipboardData.getData("text"));
            }}
            onChange={(event) => {
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

      <button className="primary-button auth-primary-action" type="submit">
        Verify identity <ArrowRight size={17} aria-hidden="true" />
      </button>
      <div className="mfa-footer">
        <span>Didn&apos;t receive a code?</span>
        <button
          className="text-link"
          type="button"
          onClick={() => setResendStatus("Code delivery will be available when MFA is connected.")}
        >
          Resend code
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
