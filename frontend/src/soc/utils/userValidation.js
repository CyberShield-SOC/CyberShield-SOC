import { normalizeEmail, validateEmail } from "../../utils/authValidation.js";
import { isPasswordPolicyMet, PASSWORD_MAX_LENGTH } from "./passwordPolicy.js";

const WORKSPACE_ROLES = new Set(["Admin", "Analyst", "Viewer"]);

function validateWorkspaceIdentity({ email, fullName, role, username }) {
  const errors = {};
  const normalizedUsername = String(username || "").trim();
  const normalizedFullName = String(fullName || "").trim();

  if (normalizedUsername.length < 3) errors.username = "Username must be at least 3 characters.";
  else if (normalizedUsername.length > 50) errors.username = "Username must be 50 characters or fewer.";

  const emailError = validateEmail(email);
  if (emailError) errors.email = emailError;

  if (normalizedFullName.length > 100) errors.fullName = "Name must be 100 characters or fewer.";

  if (!WORKSPACE_ROLES.has(role)) errors.role = "Select a supported workspace role.";
  return errors;
}

/** Password-only checks shared by account creation and password reset. */
function validateWorkspacePasswordFields({ confirmPassword, password }) {
  const errors = {};
  const value = String(password || "");

  if (value.length > PASSWORD_MAX_LENGTH) {
    errors.password = `Password must be ${PASSWORD_MAX_LENGTH} characters or fewer.`;
  } else if (!isPasswordPolicyMet(value)) {
    // The live checklist above the field spells out exactly which rule is
    // unmet; this is only the fallback message for the submit-time gate.
    errors.password = "Password does not meet all of the requirements listed below.";
  }

  if (password !== confirmPassword) errors.confirmPassword = "Passwords do not match.";

  return errors;
}

/** Validate an Admin-created account before its password ever reaches the API. */
export function validateNewWorkspaceUser({ confirmPassword, email, fullName, password, role, username }) {
  return {
    ...validateWorkspaceIdentity({ email, fullName, role, username }),
    ...validateWorkspacePasswordFields({ confirmPassword, password }),
  };
}

/** Validate identity and access fields without mixing them with password handling. */
export function validateWorkspaceUserUpdate(values) {
  return validateWorkspaceIdentity(values);
}

export function validateWorkspacePassword({ confirmPassword, password }) {
  return validateWorkspacePasswordFields({ confirmPassword, password });
}

export function normalizeNewWorkspaceUser({ email, fullName, password, role, username }) {
  return {
    username: String(username || "").trim(),
    email: normalizeEmail(email),
    fullName: String(fullName || "").trim(),
    password: String(password || ""),
    role: String(role || ""),
  };
}

export function normalizeWorkspaceUserUpdate({ email, fullName, isActive, role, username }) {
  return {
    username: String(username || "").trim(),
    email: normalizeEmail(email),
    fullName: String(fullName || "").trim(),
    role: String(role || ""),
    isActive: Boolean(isActive),
  };
}
