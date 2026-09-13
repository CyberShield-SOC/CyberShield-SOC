/**
 * Client-side mirror of backend/app/validation/passwords.py's core policy
 * (length, uppercase, lowercase, number, special character). This powers
 * the real-time requirements checklist and strength meter; it intentionally
 * does not duplicate the backend's extra guessability checks (common
 * passwords, sequential/repeated runs, product-name/username/email
 * leakage) — those stay backend-only and surface through the API error
 * message if a password slips past this checklist but still fails there.
 */

export const PASSWORD_MIN_LENGTH = 12;
export const PASSWORD_MAX_LENGTH = 256;

// Must stay identical to SPECIAL_CHARACTERS in backend/app/validation/passwords.py
// so nothing the backend accepts is rejected here, or vice versa.
export const PASSWORD_SPECIAL_CHARACTERS = "!@#$%^&*()_+-=[]{}|;:,.<>?";
const SPECIAL_CHARACTER_LIST = PASSWORD_SPECIAL_CHARACTERS.split("");

function hasSpecialCharacter(password) {
  return SPECIAL_CHARACTER_LIST.some((character) => password.includes(character));
}

export const PASSWORD_REQUIREMENTS = Object.freeze([
  {
    id: "length",
    label: `At least ${PASSWORD_MIN_LENGTH} characters`,
    test: (password) => password.length >= PASSWORD_MIN_LENGTH,
  },
  {
    id: "uppercase",
    label: "One uppercase letter (A-Z)",
    test: (password) => /[A-Z]/.test(password),
  },
  {
    id: "lowercase",
    label: "One lowercase letter (a-z)",
    test: (password) => /[a-z]/.test(password),
  },
  {
    id: "number",
    label: "One number (0-9)",
    test: (password) => /[0-9]/.test(password),
  },
  {
    id: "special",
    label: "One special character (e.g. @ # $ ! % & *)",
    test: hasSpecialCharacter,
  },
]);

/** Ordered {id, label, met} rows for the live requirements checklist. */
export function getPasswordRequirements(password) {
  const value = String(password || "");
  return PASSWORD_REQUIREMENTS.map(({ id, label, test }) => ({ id, label, met: test(value) }));
}

export function isPasswordPolicyMet(password) {
  return getPasswordRequirements(password).every((requirement) => requirement.met);
}

export function passwordsMatch(password, confirmPassword) {
  return Boolean(password) && password === confirmPassword;
}

/**
 * Weak/medium/strong classification for the strength meter. All five base
 * requirements must pass before a password can register as "strong" —
 * length beyond the minimum is what separates medium from strong once the
 * base requirements are met.
 */
export function getPasswordStrength(password) {
  const value = String(password || "");
  if (!value) return "empty";

  const metCount = PASSWORD_REQUIREMENTS.filter((requirement) => requirement.test(value)).length;
  if (metCount <= 2) return "weak";
  if (metCount < PASSWORD_REQUIREMENTS.length) return "medium";
  return value.length >= 16 ? "strong" : "medium";
}

export const PASSWORD_STRENGTH_LABELS = Object.freeze({
  empty: "",
  weak: "Weak",
  medium: "Medium",
  strong: "Strong",
});
