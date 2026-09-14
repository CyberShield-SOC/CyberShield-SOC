import test from "node:test";
import assert from "node:assert/strict";
import {
  CURRENT_DETECTION_RULE_IDS,
  CURRENT_DETECTION_RULES,
  summarizeRuleActivity,
} from "../src/soc/data/detectionRulePack.js";

test("catalogs the 30 rules registered by the backend detection engine", () => {
  assert.equal(CURRENT_DETECTION_RULE_IDS.length, 30);
  assert.deepEqual(CURRENT_DETECTION_RULE_IDS.slice(0, 8), [
    "R-101", "R-102", "R-103", "R-104", "R-105", "R-106", "R-107", "R-108",
  ]);
  const engineKeys = new Set(Object.values(CURRENT_DETECTION_RULES).map((rule) => rule.engineKey));
  for (const key of [
    "new_account_created", "privileged_group_modified", "cron_persistence",
    "security_control_disabled", "log_tampering", "ssh_key_added", "host_log_silence",
    "direct_root_login", "service_account_interactive", "login_to_nonexistent_account",
    "off_hours_login", "dormant_account_activity", "impossible_travel", "first_seen_geo_asn",
    "lateral_movement_chain", "host_sweep", "outbound_beaconing", "dns_tunneling",
    "egress_volume_anomaly", "threat_intel_match", "behavioral_anomaly_login",
    "behavioral_anomaly_egress",
  ]) {
    assert.ok(engineKeys.has(key), `missing catalog entry for ${key}`);
  }
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
  assert.equal(CURRENT_DETECTION_RULES["R-107"].engineKey, "multi_ip_successful_login");
  assert.match(CURRENT_DETECTION_RULES["R-107"].criteria, /3 distinct source IPs.+300 seconds/i);
  assert.equal(CURRENT_DETECTION_RULES["R-108"].engineKey, "sudo_after_login");
  assert.match(CURRENT_DETECTION_RULES["R-108"].criteria, /120 seconds/i);
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
