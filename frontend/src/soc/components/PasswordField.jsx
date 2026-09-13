import { useId, useState } from "react";
import { CircleAlert, CircleCheck, Eye, EyeOff } from "lucide-react";
import { getPasswordRequirements, getPasswordStrength, PASSWORD_STRENGTH_LABELS } from "../utils/passwordPolicy";

/** Password `<input>` with a show/hide toggle, styled to match soc-modal fields. */
export function PasswordInput({ error, id, ...inputProps }) {
  const [visible, setVisible] = useState(false);

  return (
    <span className="password-input-shell">
      <input
        {...inputProps}
        id={id}
        type={visible ? "text" : "password"}
        aria-invalid={Boolean(error)}
      />
      <button
        className="password-toggle-button"
        type="button"
        aria-label={visible ? "Hide password" : "Show password"}
        aria-pressed={visible}
        onClick={() => setVisible((current) => !current)}
        tabIndex={-1}
      >
        {visible ? <EyeOff size={16} aria-hidden="true" /> : <Eye size={16} aria-hidden="true" />}
      </button>
    </span>
  );
}

/** Live checklist of password requirements, one row per rule with a check/X state. */
export function PasswordRequirementsChecklist({ password }) {
  const requirements = getPasswordRequirements(password);

  return (
    <ul className="password-requirements-list" aria-live="polite">
      {requirements.map((requirement) => (
        <li key={requirement.id} data-state={requirement.met ? "met" : "unmet"}>
          {requirement.met
            ? <CircleCheck size={13} aria-hidden="true" />
            : <CircleAlert size={13} aria-hidden="true" />}
          <span>{requirement.label}</span>
        </li>
      ))}
    </ul>
  );
}

/** Weak/Medium/Strong meter, mirroring the RiskMeter track+fill visual pattern. */
export function PasswordStrengthMeter({ password }) {
  const strength = getPasswordStrength(password);
  if (strength === "empty") return null;

  return (
    <div className="password-strength-meter" data-strength={strength}>
      <div className="password-strength-track" role="meter" aria-label="Password strength" aria-valuetext={PASSWORD_STRENGTH_LABELS[strength]}>
        <span />
      </div>
      <strong>{PASSWORD_STRENGTH_LABELS[strength]}</strong>
    </div>
  );
}

/** Match/mismatch status line for a confirm-password field, live as the user types. */
export function PasswordMatchStatus({ confirmPassword, password }) {
  if (!confirmPassword) return null;
  const matches = password === confirmPassword;

  return (
    <p className="password-match-status" data-state={matches ? "met" : "unmet"} role="status">
      {matches
        ? <CircleCheck size={13} aria-hidden="true" />
        : <CircleAlert size={13} aria-hidden="true" />}
      <span>{matches ? "Passwords match" : "Passwords do not match"}</span>
    </p>
  );
}

/** Bundles the password input, live requirements checklist, and strength meter. */
export function PasswordFieldGroup({ error, id: idProp, onChange, value, ...inputProps }) {
  const generatedId = useId();
  const id = idProp || generatedId;
  const checklistId = `${id}-requirements`;

  return (
    <div className="password-field-group">
      <PasswordInput
        {...inputProps}
        id={id}
        value={value}
        error={error}
        aria-describedby={checklistId}
        onChange={onChange}
      />
      <div id={checklistId}>
        <PasswordRequirementsChecklist password={value} />
        <PasswordStrengthMeter password={value} />
      </div>
    </div>
  );
}
