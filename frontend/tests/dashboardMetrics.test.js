import test from "node:test";
import assert from "node:assert/strict";
import {
  deriveAnalystWorkload,
  deriveTelemetryReadiness,
  deriveThreatAnalysis,
} from "../src/soc/utils/dashboardMetrics.js";

const now = Date.parse("2026-07-17T12:00:00Z");

test("derives telemetry freshness without treating invalid timestamps as fresh", () => {
  assert.deepEqual(deriveTelemetryReadiness([], now), {
    state: { label: "No telemetry", tone: "critical" },
    latestIngestion: null,
    ingestionAgeMinutes: null,
    activeSources: 0,
    failedOutcomes: 0,
  });

  const result = deriveTelemetryReadiness([
    { ingestedAt: "2026-07-17T11:55:00Z", source: "auth.log", status: "failed" },
    { ingestedAt: "invalid", source: "auth.log", status: "success" },
    { timestamp: "2026-07-17T11:50:00Z", source: "firewall", status: "success" },
  ], now);
  assert.equal(result.state.label, "Live");
  assert.equal(result.ingestionAgeMinutes, 5);
  assert.equal(result.activeSources, 2);
  assert.equal(result.failedOutcomes, 1);

  const stale = deriveTelemetryReadiness([
    { ingestedAt: "2026-07-17T10:00:00Z", source: "auth.log", status: "failed" },
  ], now);
  assert.deepEqual(stale.state, { label: "Stale", tone: "warning" });
});

test("handles production-sized telemetry collections without argument overflow", () => {
  const events = Array.from({ length: 150_000 }, (_, index) => ({
    ingestedAt: new Date(now - index * 1_000).toISOString(),
    source: `source-${index % 4}`,
    status: "success",
  }));
  const result = deriveTelemetryReadiness(events, now);
  assert.equal(result.latestIngestion, now);
  assert.equal(result.activeSources, 4);
});

test("derives analyst ownership pressure from active queue records", () => {
  const result = deriveAnalystWorkload([
    { severity: "critical", status: "new", assignee: "Unassigned" },
    { severity: "high", status: "escalated", assignee: "Yugal P." },
    { severity: "medium", status: "new" },
  ], [
    { status: "investigating" },
    { status: "new" },
  ]);

  assert.deepEqual(result, {
    state: { label: "Critical attention", tone: "critical" },
    criticalActiveAlerts: 1,
    unassignedAlerts: 2,
    escalatedAlerts: 1,
    investigatingIncidents: 1,
  });
});

test("prioritizes an evidence-backed sudo finding for threat analysis", () => {
  const result = deriveThreatAnalysis([
    {
      id: "ALT-2",
      title: "Failed SSH login",
      severity: "critical",
      status: "new",
      risk: 98,
    },
    {
      id: "ALT-1",
      title: "Repeated sudo failures",
      reason: "Sudo threshold exceeded.",
      severity: "high",
      status: "investigating",
      risk: 74,
      user: "jdoe",
      sourceIp: "203.0.113.17",
      ruleId: "R-103",
      timeWindowSeconds: 300,
      evidenceIds: ["EVT-1", "EVT-2", "EVT-3"],
    },
  ], []);

  assert.equal(result.alertId, "ALT-1");
  assert.equal(result.category, "Privilege escalation");
  assert.equal(result.title, "Repeated sudo failures for 'jdoe': 3 failures in 300s.");
  assert.match(result.description, /Possible privilege escalation attempt/);
  assert.equal(result.evidenceCount, 3);
});

test("uses repeated failed events when no active alert is available", () => {
  const result = deriveThreatAnalysis([], [
    { user: "analyst", sourceIp: "198.51.100.8", status: "failed", timestamp: "2026-07-17T11:55:00Z" },
    { user: "analyst", sourceIp: "198.51.100.8", status: "failed", timestamp: "2026-07-17T11:57:00Z" },
    { user: "analyst", sourceIp: "198.51.100.8", status: "failed", timestamp: "2026-07-17T12:00:00Z" },
  ]);

  assert.equal(result.category, "Behavioral correlation");
  assert.equal(result.title, "Repeated authentication failures for 'analyst': 3 failures in 300s.");
  assert.equal(result.sourceIp, "198.51.100.8");
});

test("preserves an evidence count embedded in a server-authored alert reason", () => {
  const result = deriveThreatAnalysis([{
    id: "ALT-3",
    title: "Brute-force login",
    reason: "Brute-force detected from 203.0.113.4: 5 failed login attempts within 60s.",
    severity: "critical",
    status: "new",
  }], []);

  assert.equal(result.evidenceCount, 5);
});

test("ignores terminal sudo alerts when selecting the active threat finding", () => {
  const result = deriveThreatAnalysis([
    { id: "ALT-1", title: "Repeated sudo failures", status: "resolved", severity: "critical", risk: 100 },
    { id: "ALT-2", title: "Suspicious successful login", status: "new", severity: "high", risk: 80 },
  ], []);

  assert.equal(result.alertId, "ALT-2");
  assert.equal(result.title, "Suspicious successful login");
});
