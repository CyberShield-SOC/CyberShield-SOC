import test from "node:test";
import assert from "node:assert/strict";
import {
  normalizeNewWorkspaceUser,
  normalizeWorkspaceUserUpdate,
  validateNewWorkspaceUser,
  validateWorkspacePassword,
  validateWorkspaceUserUpdate,
} from "../src/soc/utils/userValidation.js";

const validUser = {
  username: " analyst-demo ",
  email: " Analyst.Demo@CyberShield.Local ",
  fullName: " Analyst Demo ",
  password: "LongLocalPassword!42",
  confirmPassword: "LongLocalPassword!42",
  role: "Analyst",
};

test("validates Admin-created workspace accounts before submission", () => {
  assert.deepEqual(validateNewWorkspaceUser(validUser), {});
  assert.deepEqual(validateNewWorkspaceUser({ ...validUser, password: "short", confirmPassword: "different", role: "Owner" }), {
    password: "Use a password with at least 12 characters.",
    confirmPassword: "Passwords do not match.",
    role: "Select a supported workspace role.",
  });
});

test("normalizes account identity fields but never returns the confirmation password", () => {
  assert.deepEqual(normalizeNewWorkspaceUser(validUser), {
    username: "analyst-demo",
    email: "analyst.demo@cybershield.local",
    fullName: "Analyst Demo",
    password: "LongLocalPassword!42",
    role: "Analyst",
  });
});

test("validates and normalizes Admin account edits", () => {
  const update = {
    username: " viewer-one ",
    email: " VIEWER.ONE@Example.test ",
    fullName: " Viewer One ",
    role: "Viewer",
    isActive: false,
  };
  assert.deepEqual(validateWorkspaceUserUpdate(update), {});
  assert.deepEqual(normalizeWorkspaceUserUpdate(update), {
    username: "viewer-one",
    email: "viewer.one@example.test",
    fullName: "Viewer One",
    role: "Viewer",
    isActive: false,
  });
});

test("validates password resets independently of identity fields", () => {
  assert.deepEqual(validateWorkspacePassword({ password: "ResetPassphrase-42!", confirmPassword: "ResetPassphrase-42!" }), {});
  assert.deepEqual(validateWorkspacePassword({ password: "short", confirmPassword: "different" }), {
    password: "Use a password with at least 12 characters.",
    confirmPassword: "Passwords do not match.",
  });
});
