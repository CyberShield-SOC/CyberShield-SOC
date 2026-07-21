import test from "node:test";
import assert from "node:assert/strict";
import {
  CURRENT_DETECTION_RULE_IDS,
  CURRENT_DETECTION_RULES,
  summarizeRuleActivity,
} from "../src/soc/data/detectionRulePack.js";

test("catalogs the six rules registered by the backend detection engine", () => {
  assert.deepEqual(CURRENT_DETECTION_RULE_IDS, [
    "R-101", "R-102", "R-103", "R-104", "R-105", "R-106",
  ]);
  assert.equal(CURRENT_DETECTION_RULES["R-101"].engineKey, "brute_force_login");
  assert.match(CURRENT_DETECTION_RULES["R-101"].criteria, /5 failed login attempts.+60 seconds/i);
  assert.equal(CURRENT_DETECTION_RULES["R-102"].engineKey, "invalid_user_enumeration");
  assert.match(CURRENT_DETECTION_RULES["R-102"].criteria, /3 distinct usernames.+600 seconds/i);
  assert.equal(CURRENT_DETECTION_RULES["R-103"].engineKey, "sudo_failure");
  assert.match(CURRENT_DETECTION_RULES["R-103"].criteria, /3 failed sudo attempts.+300 seconds/i);
  assert.equal(CURRENT_DETECTION_RULES["R-104"].engineKey, "password_spraying");
  assert.match(CURRENT_DETECTION_RULES["R-104"].criteria, /5 distinct source IPs.+600 seconds/i);
  assert.equal(CURRENT_DETECTION_RULES["R-105"].engineKey, "credential_stuffing_success");
  assert.match(CURRENT_DETECTION_RULES["R-105"].criteria, /5 failed login attempts.+60 seconds.+120 seconds/i);
  assert.equal(CURRENT_DETECTION_RULES["R-106"].engineKey, "port_scan");
  assert.match(CURRENT_DETECTION_RULES["R-106"].criteria, /10 scan events.+60 seconds/i);
});

test("summarizes active and terminal alert activity without accepting invalid dates", () => {
  const summary = summarizeRuleActivity("R-101", [
    { ruleId: "R-101", status: "new", createdAt: "2026-07-18T10:00:00Z" },
    { ruleId: "R-101", status: "resolved", createdAt: "2026-07-18T11:00:00Z" },
    { ruleId: "R-101", status: "closed", createdAt: "not-a-date" },
    { ruleId: "R-102", status: "new", createdAt: "2026-07-18T12:00:00Z" },
  ]);

  assert.deepEqual(summary, {
    active: 1,
    latest: "2026-07-18T11:00:00.000Z",
    total: 3,
  });
  assert.deepEqual(summarizeRuleActivity("R-103", null), {
    active: 0,
    latest: null,
    total: 0,
  });
});
