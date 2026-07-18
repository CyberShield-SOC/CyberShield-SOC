import { useState } from "react";
import { CircleAlert, Eye, EyeOff } from "lucide-react";

export function FormField({
  label,
  icon: Icon,
  inputRef,
  type = "text",
  error,
  ...inputProps
}) {
  const [isVisible, setIsVisible] = useState(false);
  const isPassword = type === "password";
  const errorId = error && inputProps.id ? `${inputProps.id}-error` : undefined;

  return (
    <div className="block">
      {label && (
        <label className="field-label" htmlFor={inputProps.id}>
          {label}
        </label>
      )}
      <span className={`field-shell ${error ? "has-error" : ""}`}>
        <Icon size={15} className="field-leading-icon" aria-hidden="true" />
        <input
          ref={inputRef}
          type={isPassword && isVisible ? "text" : type}
          aria-invalid={Boolean(error)}
          aria-describedby={errorId}
          {...inputProps}
        />
        {isPassword && (
          <button
            className="field-action"
            type="button"
            aria-label={isVisible ? "Hide password" : "Show password"}
            aria-pressed={isVisible}
            onClick={() => setIsVisible((current) => !current)}
          >
            {isVisible ? <EyeOff size={18} /> : <Eye size={18} />}
          </button>
        )}
      </span>
      {error && (
        <span className="field-error" id={errorId} role="alert">
          <CircleAlert size={12} aria-hidden="true" /> {error}
        </span>
      )}
    </div>
  );
}
