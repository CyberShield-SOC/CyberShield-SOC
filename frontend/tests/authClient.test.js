import test from "node:test";
import assert from "node:assert/strict";
import {
  AuthRequestError,
  getAuthFailureMessage,
  readAuthUser,
} from "../src/services/authClient.js";

test("uses a privacy-preserving message for rejected credentials", () => {
  assert.equal(
    getAuthFailureMessage(401),
    "The username or password you entered is incorrect",
  );
});

test("keeps throttling and service failures distinct", () => {
  assert.match(getAuthFailureMessage(429), /Too many sign-in attempts/);
  assert.match(getAuthFailureMessage(503), /secure service could not complete/);
});

test("rejects malformed successful authentication responses", () => {
  assert.throws(() => readAuthUser({ user: null }), AuthRequestError);
  assert.throws(() => readAuthUser({ user: { id: 1 } }), AuthRequestError);
  assert.equal(readAuthUser({
    user: {
      id: 1,
      username: "analyst",
      email: "analyst@cybershield.io",
      is_active: true,
      role: "Analyst",
    },
  }).username, "analyst");
  assert.throws(() => readAuthUser({
    user: {
      id: 1,
      username: "analyst",
      email: "analyst@cybershield.io",
      is_active: true,
      role: "Owner",
    },
  }), AuthRequestError);
});
