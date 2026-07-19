const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

export function normalizeEmail(value) {
  return String(value ?? "").trim().toLowerCase();
}

export function validateCredentials({ email, password }) {
  const errors = {};
  const emailError = validateEmail(email);

  if (emailError) errors.email = emailError;

  if (!password) {
    errors.password = "Enter your password.";
  }

  return errors;
}

export function validateEmail(email) {
  const normalizedEmail = normalizeEmail(email);
  if (!normalizedEmail) return "Enter your email address.";
  if (!EMAIL_PATTERN.test(normalizedEmail)) return "Enter a valid email address.";
  return "";
}

export function sanitizeOtp(value) {
  return String(value ?? "").replace(/\D/g, "");
}

export function isCompleteOtp(digits) {
  return Array.isArray(digits) && digits.length === 6 && digits.every((digit) => /^\d$/.test(digit));
}
