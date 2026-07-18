import test from "node:test";
import assert from "node:assert/strict";
import { deriveWorkspaceCounts, filterAlertsForPicker, isActiveAlert, isQuickResolvableAlert } from "../src/soc/utils/workspaceSelectors.js";

test("derives synchronized navigation and notification counts", () => {
  const alerts = [
    { status: "new" },
    { status: "investigating" },
    { status: "contained" },
    { status: "resolved" },
  ];
  const incidents = [{ status: "new" }, { status: "resolved" }, { status: "escalated" }];
  const notifications = [{ read: false }, { read: true }, { read: false }];

  assert.equal(isActiveAlert(alerts[0]), true);
  assert.equal(isActiveAlert(alerts[2]), false);
  assert.equal(isActiveAlert({ status: "false positive" }), false);
  assert.deepEqual(deriveWorkspaceCounts(alerts, incidents, notifications), {
    activeAlerts: 2,
    openIncidents: 2,
    unreadNotifications: 2,
  });
});

test("keeps escalated alerts active and excludes terminal incidents", () => {
  const counts = deriveWorkspaceCounts(
    [{ status: "escalated" }, { status: "resolved" }],
    [{ status: "investigating" }, { status: "false positive" }],
  );
  assert.equal(counts.activeAlerts, 1);
  assert.equal(counts.openIncidents, 1);
});

test("searches quick-resolve alerts across analyst-facing identifiers", () => {
  const alerts = [
    { id: "ALT-001", title: "Failed SSH login", severity: "critical", status: "new", sourceIp: "203.0.113.4", user: "root", ruleId: "R-101", ruleName: "Brute force" },
    { id: "ALT-002", title: "Suspicious PowerShell", severity: "high", status: "investigating", sourceIp: "10.0.8.41", user: "analyst", ruleId: "R-411", ruleName: "Unsigned execution" },
  ];

  assert.deepEqual(filterAlertsForPicker(alerts, "203.0.113").map((alert) => alert.id), ["ALT-001"]);
  assert.deepEqual(filterAlertsForPicker(alerts, "powershell").map((alert) => alert.id), ["ALT-002"]);
  assert.deepEqual(filterAlertsForPicker(alerts, "R-101").map((alert) => alert.id), ["ALT-001"]);
  assert.equal(filterAlertsForPicker(alerts, "").length, 2);
});

test("quick resolve excludes completed alerts and alerts with completed incidents", () => {
  const activeAlert = { id: "ALT-001", sourceAlertId: 41, status: "investigating", evidenceIds: ["EVT-1"] };
  assert.equal(isQuickResolvableAlert(activeAlert, []), true);
  assert.equal(isQuickResolvableAlert({ ...activeAlert, status: "resolved" }, []), false);
  assert.equal(isQuickResolvableAlert(activeAlert, [{ sourceAlertId: 41, status: "resolved", eventIds: [] }]), false);
  assert.equal(isQuickResolvableAlert(activeAlert, [{ sourceAlertId: 41, status: "investigating", eventIds: [] }]), true);
});
