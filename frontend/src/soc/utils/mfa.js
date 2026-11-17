// Pure helpers for the authenticator-app (TOTP) screens. Codes are checked
// by the server (backend/app/services/totp.py); nothing here verifies one.

const RECOVERY_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789";
const RECOVERY_LENGTH = 10;

export function normalizeMfaState(payload) {
  const enabled = payload?.totp_enabled === true || payload?.totpEnabled === true;
  const remaining = Number(payload?.recovery_codes_remaining ?? payload?.recoveryCodesRemaining);
  return {
    method: enabled ? "totp" : "email",
    totpEnabled: enabled,
    totpEnabledAt: enabled ? payload?.totp_enabled_at || payload?.totpEnabledAt || null : null,
    recoveryCodesRemaining: enabled && Number.isSafeInteger(remaining) && remaining > 0 ? remaining : 0,
  };
}

export function normalizeTotpSetup(payload) {
  const secret = String(payload?.secret || "").replace(/\s+/g, "").toUpperCase();
  const qrSvg = String(payload?.qr_svg || payload?.qrSvg || "");
  if (!/^[A-Z2-7]{16,64}$/.test(secret)) {
    throw new Error("The secure service returned an invalid setup key. Please try again.");
  }
  return {
    secret,
    otpauthUri: String(payload?.otpauth_uri || payload?.otpauthUri || ""),
    qrSvg: qrSvg.startsWith("<svg") ? qrSvg : "",
  };
}

/** "JBSWY3DPEHPK3PXP" -> "JBSW Y3DP EHPK 3PXP": easier to type by hand. */
export function formatSetupKey(secret) {
  return String(secret || "").replace(/\s+/g, "").replace(/(.{4})(?=.)/g, "$1 ");
}

/** An SVG string as an <img> source. data: images are allowed by the CSP;
 * inline SVG markup from a response is deliberately never injected. */
export function svgDataUrl(svg) {
  const text = String(svg || "");
  return text.startsWith("<svg") ? `data:image/svg+xml;charset=utf-8,${encodeURIComponent(text)}` : "";
}

export function sanitizeTotpCode(value) {
  return String(value ?? "").replace(/\D/g, "").slice(0, 6);
}

export function isTotpCode(value) {
  return /^\d{6}$/.test(String(value ?? ""));
}

/** Recovery codes are typed by hand: accept any case, spaces or a hyphen. */
export function normalizeRecoveryCode(value) {
  const cleaned = String(value ?? "").toLowerCase().replace(/[\s-]/g, "");
  if (cleaned.length !== RECOVERY_LENGTH) return "";
  if (![...cleaned].every((char) => RECOVERY_ALPHABET.includes(char))) return "";
  return `${cleaned.slice(0, 5)}-${cleaned.slice(5)}`;
}

/** What a sign-in or confirmation field holds: a code, a recovery code, or neither. */
export function secondFactorInput(value) {
  const digits = String(value ?? "").trim();
  if (isTotpCode(digits)) return { kind: "totp", code: digits };
  const recovery = normalizeRecoveryCode(value);
  if (recovery) return { kind: "recovery", code: recovery };
  return { kind: "", code: "" };
}

export function recoveryCodesFile(codes, { account = "", generatedAt = new Date() } = {}) {
  const lines = [
    "CyberShield SOC recovery codes",
    account ? `Account: ${account}` : "",
    `Generated: ${generatedAt.toISOString().slice(0, 10)}`,
    "",
    "Each code signs you in once if you cannot use your authenticator app.",
    "Keep them somewhere safe and separate from your password.",
    "",
    ...codes,
    "",
  ];
  return lines.filter((line, index) => line !== "" || index > 2).join("\n");
}

export function recoveryCodesWarning(remaining) {
  if (remaining === 0) return "You have no recovery codes left. Generate a new set now.";
  if (remaining <= 2) return `Only ${remaining} recovery ${remaining === 1 ? "code is" : "codes are"} left. Generate a new set soon.`;
  return "";
}
