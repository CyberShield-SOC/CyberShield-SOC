import assert from "node:assert/strict";
import test from "node:test";

import {
  formatSetupKey,
  isTotpCode,
  normalizeMfaState,
  normalizeRecoveryCode,
  normalizeTotpSetup,
  recoveryCodesFile,
  recoveryCodesWarning,
  sanitizeTotpCode,
  secondFactorInput,
  svgDataUrl,
} from "../src/soc/utils/mfa.js";
import { SAMPLE_RECOVERY_CODES, SAMPLE_TOTP_SETUP } from "../src/soc/data/sampleMfa.js";

test("MFA state defaults to emailed codes and never reports codes without an authenticator", () => {
  assert.deepEqual(normalizeMfaState(null), {
    method: "email", totpEnabled: false, totpEnabledAt: null, recoveryCodesRemaining: 0,
  });
  assert.deepEqual(
    normalizeMfaState({ totp_enabled: true, totp_enabled_at: "2026-11-17T08:00:00+00:00", recovery_codes_remaining: 7 }),
    { method: "totp", totpEnabled: true, totpEnabledAt: "2026-11-17T08:00:00+00:00", recoveryCodesRemaining: 7 },
  );
  assert.equal(normalizeMfaState({ totp_enabled: false, recovery_codes_remaining: 5 }).recoveryCodesRemaining, 0);
  assert.equal(normalizeMfaState({ totp_enabled: "true" }).totpEnabled, false);
});

test("a setup response must carry a base32 key, and only real SVG is kept", () => {
  const setup = normalizeTotpSetup({ secret: "jbsw y3dp ehpk 3pxp", otpauth_uri: "otpauth://totp/x", qr_svg: "<svg></svg>" });
  assert.deepEqual(setup, { secret: "JBSWY3DPEHPK3PXP", otpauthUri: "otpauth://totp/x", qrSvg: "<svg></svg>" });
  assert.equal(normalizeTotpSetup({ secret: "JBSWY3DPEHPK3PXP", qr_svg: "<img src=x onerror=alert(1)>" }).qrSvg, "");
  assert.throws(() => normalizeTotpSetup({ secret: "not base32!" }), /invalid setup key/);
  assert.throws(() => normalizeTotpSetup({}), /invalid setup key/);
});

test("the setup key is grouped in fours for typing", () => {
  assert.equal(formatSetupKey("JBSWY3DPEHPK3PXP"), "JBSW Y3DP EHPK 3PXP");
  assert.equal(formatSetupKey("JBSW Y3DP EH"), "JBSW Y3DP EH");
  assert.equal(formatSetupKey(""), "");
});

test("QR markup becomes a data URL for an img, never raw markup", () => {
  const url = svgDataUrl('<svg xmlns="http://www.w3.org/2000/svg"><path d="M0 0h1"/></svg>');
  assert.ok(url.startsWith("data:image/svg+xml;charset=utf-8,%3Csvg"));
  assert.ok(!url.includes("<"));
  assert.equal(svgDataUrl("<script>alert(1)</script>"), "");
  assert.equal(svgDataUrl(null), "");
});

test("authenticator codes are six ASCII digits", () => {
  assert.equal(sanitizeTotpCode(" 12 34-56 78"), "123456");
  assert.equal(isTotpCode("123456"), true);
  assert.equal(isTotpCode("12345"), false);
  assert.equal(isTotpCode("١٢٣٤٥٦"), false);
});

test("recovery codes are accepted however they are typed", () => {
  assert.equal(normalizeRecoveryCode("KQ7MN 2XVBD"), "kq7mn-2xvbd");
  assert.equal(normalizeRecoveryCode("kq7mn-2xvbd"), "kq7mn-2xvbd");
  assert.equal(normalizeRecoveryCode("kq7mn2xvb"), "");
  assert.equal(normalizeRecoveryCode("kq7mn-2xvb0"), ""); // 0 is not in the alphabet
  assert.equal(normalizeRecoveryCode("123456"), "");
});

test("a second-factor field recognises which kind of code it holds", () => {
  assert.deepEqual(secondFactorInput(" 123456 "), { kind: "totp", code: "123456" });
  assert.deepEqual(secondFactorInput("KQ7MN-2XVBD"), { kind: "recovery", code: "kq7mn-2xvbd" });
  assert.deepEqual(secondFactorInput("12345"), { kind: "", code: "" });
  assert.deepEqual(secondFactorInput(""), { kind: "", code: "" });
});

test("the recovery-code file names the account and lists every code", () => {
  const text = recoveryCodesFile(["aaaaa-bbbbb", "ccccc-ddddd"], {
    account: "analyst@example.test",
    generatedAt: new Date("2026-11-17T08:00:00Z"),
  });

  assert.equal(text, [
    "CyberShield SOC recovery codes",
    "Account: analyst@example.test",
    "Generated: 2026-11-17",
    "",
    "Each code signs you in once if you cannot use your authenticator app.",
    "Keep them somewhere safe and separate from your password.",
    "",
    "aaaaa-bbbbb",
    "ccccc-ddddd",
    "",
  ].join("\n"));
  assert.ok(!recoveryCodesFile(["aaaaa-bbbbb"], { generatedAt: new Date("2026-11-17T08:00:00Z") }).includes("Account:"));
});

test("a warning appears only when recovery codes are running out", () => {
  assert.equal(recoveryCodesWarning(8), "");
  assert.equal(recoveryCodesWarning(3), "");
  assert.match(recoveryCodesWarning(2), /Only 2 recovery codes are left/);
  assert.match(recoveryCodesWarning(1), /Only 1 recovery code is left/);
  assert.match(recoveryCodesWarning(0), /no recovery codes left/);
});

test("the sample-mode setup is a well-formed stand-in for the server response", () => {
  const setup = normalizeTotpSetup(SAMPLE_TOTP_SETUP);
  assert.equal(setup.secret, "JBSWY3DPEHPK3PXP");
  assert.ok(setup.otpauthUri.includes(`secret=${setup.secret}`));
  assert.ok(setup.qrSvg.startsWith("<svg"));
  assert.equal(SAMPLE_RECOVERY_CODES.length, 8);
  assert.ok(SAMPLE_RECOVERY_CODES.every((code) => normalizeRecoveryCode(code) === code));
});
