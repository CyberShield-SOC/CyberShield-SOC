import test from "node:test";
import assert from "node:assert/strict";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { createServer } from "vite";
import { normalizeWorkflowEvent } from "../src/soc/utils/workflowHistory.js";
import { canReadWorkspace, canManageRules, canExportReports } from "../src/utils/permissions.js";

test("role policy permits readers and rule authors while denying unknown or inactive roles", () => {
  for (const role of ["Admin", "Analyst", "Viewer"]) {
    const user = { role };
    assert.equal(canReadWorkspace(user), true);
    assert.equal(canExportReports(user), true);
    assert.equal(canManageRules(user), role !== "Viewer");
    assert.equal(canReadWorkspace({ ...user, is_active: false }), false);
  }
  for (const user of [{}, { role: "admin" }, { role: "Unknown" }]) {
    assert.equal(canReadWorkspace(user), false); assert.equal(canManageRules(user), false); assert.equal(canExportReports(user), false);
  }
  assert.equal(canManageRules(null), true);
});

test("history retains actors, original resolution snapshots, notes and precise changes", () => {
  const after = { status: "RESOLVED", resolution_note: "kept_exactly\non two lines", version: 5 };
  const event = normalizeWorkflowEvent({ id: 9, event_type: "INCIDENT_RESOLVED", occurred_at: "2026-10-25T12:00:00Z", actor_name: "Analyst", reason: "Contained", note: "Source verified", before: { status: "INVESTIGATING" }, after });
  assert.equal(event.actor, "Analyst"); assert.equal(event.after, after);
  assert.equal(event.changes.find((change) => change.label === "Resolution note").after, after.resolution_note);
  assert.match(event.detail, /INVESTIGATING → RESOLVED/); assert.match(event.detail, /Source verified/);
  assert.ok(!event.changes.some((change) => change.label === "version"));
});

let server;
test.after(async () => { if (server) await server.close(); });
async function components() {
  server ||= await createServer({ appType: "custom", logLevel: "silent", server: { middlewareMode: true } });
  return server.ssrLoadModule("/src/soc/components/InvestigationTimeline.jsx");
}

test("timeline paginates all recorded events and renders note contents safely", async () => {
  const { InvestigationTimeline } = await components();
  const items = Array.from({ length: 12 }, (_, id) => normalizeWorkflowEvent({ id, event_type: "NOTE_ADDED", occurred_at: "2026-10-25T12:00:00Z", actor_name: "Analyst", note: `<script>note ${id}</script>` }));
  const html = renderToStaticMarkup(React.createElement(InvestigationTimeline, { items }));
  assert.match(html, /1–10 of 12/); assert.match(html, /Next/); assert.match(html, /&lt;script&gt;note 0/); assert.doesNotMatch(html, /<script>/);
  const errorHtml = renderToStaticMarkup(React.createElement(InvestigationTimeline, { items: [], error: "Unavailable", onRetry() {} }));
  assert.match(errorHtml, /Retry history/); assert.doesNotMatch(errorHtml, /No recorded changes/);
});

test("resolution details show recorded decisions and honest legacy fallbacks", async () => {
  const { ResolutionDetails } = await components();
  const html = renderToStaticMarkup(React.createElement(ResolutionDetails, { incident: { status: "resolved", resolutionReason: "Contained", resolutionNote: "Credentials rotated", completedBy: "Analyst", completedAt: "2026-10-25T12:00:00Z" } }));
  assert.match(html, /Contained/); assert.match(html, /Credentials rotated/); assert.match(html, /Analyst/);
  const legacy = renderToStaticMarkup(React.createElement(ResolutionDetails, { incident: { status: "false positive", resolutionReason: "LEGACY_UNKNOWN" } }));
  assert.match(legacy, /Not recorded for this historical incident/); assert.doesNotMatch(legacy, /LEGACY_UNKNOWN/);
  assert.equal(renderToStaticMarkup(React.createElement(ResolutionDetails, { incident: { status: "open" } })), "");
});

test("direct links to rule authoring obey the same role restrictions as the controls", async () => {
  await components();
  const { canAccessSocRoute, SOC_ROUTES } = await server.ssrLoadModule("/src/hooks/useAuthRoute.js");
  assert.equal(canAccessSocRoute(SOC_ROUTES.ruleBuilder, { role: "Viewer" }), false);
  assert.equal(canAccessSocRoute(SOC_ROUTES.ruleBuilder, { role: "Analyst" }), true);
  assert.equal(canAccessSocRoute(SOC_ROUTES.reports, { role: "Viewer" }), true);
  assert.equal(canAccessSocRoute(SOC_ROUTES.dashboard, { role: "Unknown" }), false);
});
