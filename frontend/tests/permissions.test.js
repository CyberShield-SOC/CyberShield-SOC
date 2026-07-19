import test from "node:test";
import assert from "node:assert/strict";
import {
  canAdministerWorkspace,
  canMutateInvestigations,
  canOpenUserManagement,
} from "../src/utils/permissions.js";


test("enforces the complete connected role matrix", () => {
  const admin = { role: "Admin" };
  const analyst = { role: "Analyst" };
  const viewer = { role: "Viewer" };

  assert.equal(canMutateInvestigations(admin), true);
  assert.equal(canMutateInvestigations(analyst), true);
  assert.equal(canMutateInvestigations(viewer), false);
  assert.equal(canAdministerWorkspace(admin), true);
  assert.equal(canAdministerWorkspace(analyst), false);
  assert.equal(canAdministerWorkspace(viewer), false);
  assert.equal(canOpenUserManagement(admin), true);
  assert.equal(canOpenUserManagement(analyst), false);
  assert.equal(canOpenUserManagement(viewer), false);
});


test("allows tab-local sample mode without trusting malformed connected roles", () => {
  assert.equal(canMutateInvestigations(null), true);
  assert.equal(canAdministerWorkspace(null), true);
  assert.equal(canMutateInvestigations({}), false);
  assert.equal(canMutateInvestigations({ role: "admin" }), false);
  assert.equal(canAdministerWorkspace({ role: "Owner" }), false);
});
