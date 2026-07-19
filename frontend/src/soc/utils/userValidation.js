import { normalizeEmail, validateEmail } from "../../utils/authValidation.js";

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

/** Validate an Admin-created account before its password ever reaches the API. */
export function validateNewWorkspaceUser({ confirmPassword, email, fullName, password, role, username }) {
  const errors = validateWorkspaceIdentity({ email, fullName, role, username });

  if (String(password || "").length < 12) errors.password = "Use a password with at least 12 characters.";
  else if (String(password).length > 256) errors.password = "Password must be 256 characters or fewer.";

  if (password !== confirmPassword) errors.confirmPassword = "Passwords do not match.";

  return errors;
}

/** Validate identity and access fields without mixing them with password handling. */
export function validateWorkspaceUserUpdate(values) {
  return validateWorkspaceIdentity(values);
}

export function validateWorkspacePassword({ confirmPassword, password }) {
  const errors = {};
  if (String(password || "").length < 12) errors.password = "Use a password with at least 12 characters.";
  else if (String(password).length > 256) errors.password = "Password must be 256 characters or fewer.";
  if (password !== confirmPassword) errors.confirmPassword = "Passwords do not match.";
  return errors;
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
