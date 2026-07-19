import test from "node:test";
import assert from "node:assert/strict";
import {
  isCompleteOtp,
  normalizeEmail,
  sanitizeOtp,
  validateCredentials,
  validateEmail,
} from "../src/utils/authValidation.js";

test("normalizes email without changing password input", () => {
  assert.equal(normalizeEmail("  Analyst@CyberShield.IO "), "analyst@cybershield.io");
  assert.equal(normalizeEmail(null), "");
});

test("returns clear credential validation errors", () => {
  assert.deepEqual(validateCredentials({ email: "invalid", password: "" }), {
    email: "Enter a valid email address.",
    password: "Enter your password.",
  });
  assert.deepEqual(validateCredentials({ email: "analyst@example.com", password: "secret" }), {});
});

test("validates recovery email without exposing account state", () => {
  assert.equal(validateEmail(""), "Enter your email address.");
  assert.equal(validateEmail("not-an-email"), "Enter a valid email address.");
  assert.equal(validateEmail("analyst@example.com"), "");
});

test("accepts only complete numeric one-time codes", () => {
  assert.equal(sanitizeOtp("12a-34 56"), "123456");
  assert.equal(sanitizeOtp(null), "");
  assert.equal(isCompleteOtp(["1", "2", "3", "4", "5", "6"]), true);
  assert.equal(isCompleteOtp(["1", "2", "", "4", "5", "6"]), false);
  assert.equal(isCompleteOtp(null), false);
});
