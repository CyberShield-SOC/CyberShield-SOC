import test from "node:test";
import assert from "node:assert/strict";
import {
  auditActionLabel,
  auditQueryParams,
  auditTargetLabel,
  filterAuditEvents,
  normalizeAuditEvent,
  summarizeAuditDetail,
} from "../src/soc/utils/auditLog.js";
import { canAccessSocRoute, SOC_ROUTES } from "../src/hooks/useAuthRoute.js";

const RAW = {
  id: 42,
  occurred_at: "2026-11-16T10:15:00+00:00",
  actor_user_id: 7,
  actor_name: "CyberShield Admin",
  actor_role: "Admin",
  action: "user.role.change",
  outcome: "SUCCESS",
  target_type: "user",
  target_id: "12",
  target_label: "marvellous",
  ip_address: "198.51.100.10",
  user_agent: "Mozilla/5.0",
  detail: { from: "Viewer", to: "Analyst" },
};

test("normalizes a backend audit event into the page shape", () => {
  const event = normalizeAuditEvent(RAW);
  assert.equal(event.id, 42);
  assert.equal(event.occurredAt, "2026-11-16T10:15:00.000Z");
  assert.equal(event.actorName, "CyberShield Admin");
  assert.equal(event.outcome, "success");
  assert.equal(event.targetLabel, "marvellous");
  assert.deepEqual(event.detail, { from: "Viewer", to: "Analyst" });
});

test("rejects rows without a usable id and tolerates missing fields", () => {
  assert.equal(normalizeAuditEvent({ ...RAW, id: "abc" }), null);
  assert.equal(normalizeAuditEvent(null), null);

  const sparse = normalizeAuditEvent({ id: 1, action: "auth.logout", outcome: "FAILURE", detail: ["not", "an", "object"] });
  assert.equal(sparse.actorName, "Anonymous");
  assert.equal(sparse.outcome, "failure");
  assert.equal(sparse.occurredAt, "");
  assert.deepEqual(sparse.detail, {});
});

test("labels known actions and falls back to the raw name", () => {
  assert.equal(auditActionLabel("user.role.change"), "Changed an account's role");
  assert.equal(auditActionLabel("something.new"), "something.new");
  assert.equal(auditActionLabel(""), "Unknown action");
});

test("summarizes detail as plain facts", () => {
  assert.deepEqual(summarizeAuditDetail({ from: "Viewer", to: "Analyst" }), ["Viewer to Analyst"]);
  assert.deepEqual(summarizeAuditDetail({ from: true, to: false }), ["yes to no"]);
  assert.deepEqual(
    summarizeAuditDetail({ changes: { role: { from: "Analyst", to: "Viewer" }, full_name: { from: null, to: "Sam" } } }),
    ["role: Analyst to Viewer", "full name: none to Sam"],
  );
  assert.deepEqual(
    summarizeAuditDetail({ reason: "invalid_credentials", account_known: true }),
    ["reason: invalid_credentials", "account known: yes"],
  );
  assert.deepEqual(summarizeAuditDetail({ updates: { fail_threshold: 8 } }), ["updates: fail threshold 8"]);
  assert.deepEqual(summarizeAuditDetail(null), []);
});

test("names the target, falling back to its type and id", () => {
  assert.equal(auditTargetLabel(normalizeAuditEvent(RAW)), "marvellous");
  assert.equal(auditTargetLabel(normalizeAuditEvent({ ...RAW, target_label: null, target_type: "ml_model" })), "ml model 12");
  assert.equal(auditTargetLabel(normalizeAuditEvent({ ...RAW, target_label: null, target_id: null })), "");
});

test("builds the query string the backend expects", () => {
  assert.equal(auditQueryParams(), "limit=50");
  assert.equal(
    auditQueryParams({ category: "auth", outcome: "failure", actor: "  sam  ", beforeId: 90, limit: 20 }),
    "category=auth&outcome=FAILURE&actor=sam&before_id=90&limit=20",
  );
});

test("sample-mode filtering mirrors the backend: newest first, filtered, paged", () => {
  const events = [1, 2, 3, 4, 5].map((id) => normalizeAuditEvent({
    ...RAW,
    id,
    action: id % 2 ? "auth.login.password" : "user.create",
    outcome: id === 5 ? "FAILURE" : "SUCCESS",
    actor_name: id === 1 ? "Sam Analyst" : "CyberShield Admin",
  }));

  const firstPage = filterAuditEvents(events, { limit: 2 });
  assert.deepEqual(firstPage.events.map((event) => event.id), [5, 4]);
  assert.equal(firstPage.nextBeforeId, 4);

  const secondPage = filterAuditEvents(events, { limit: 2, beforeId: 4 });
  assert.deepEqual(secondPage.events.map((event) => event.id), [3, 2]);

  const lastPage = filterAuditEvents(events, { limit: 2, beforeId: 2 });
  assert.deepEqual(lastPage.events.map((event) => event.id), [1]);
  assert.equal(lastPage.nextBeforeId, null);

  assert.deepEqual(filterAuditEvents(events, { category: "auth" }).events.map((event) => event.id), [5, 3, 1]);
  assert.deepEqual(filterAuditEvents(events, { outcome: "failure" }).events.map((event) => event.id), [5]);
  assert.deepEqual(filterAuditEvents(events, { actor: "SAM" }).events.map((event) => event.id), [1]);
});

test("the audit log route is limited to administrators", () => {
  assert.equal(canAccessSocRoute(SOC_ROUTES.auditLog, { role: "Admin" }), true);
  assert.equal(canAccessSocRoute(SOC_ROUTES.auditLog, { role: "Analyst" }), false);
  assert.equal(canAccessSocRoute(SOC_ROUTES.auditLog, { role: "Viewer" }), false);
  assert.equal(canAccessSocRoute(SOC_ROUTES.auditLog, null), true);
});
