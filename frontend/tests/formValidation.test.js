import test from "node:test";
import assert from "node:assert/strict";
import {
  parseNoteTags,
  validateAnalystNote,
  validateIncidentDraft,
  validateWorkspaceSettings,
} from "../src/soc/utils/formValidation.js";

test("returns concise analyst-note validation guidance", () => {
  assert.deepEqual(validateAnalystNote({ title: "A", body: "short" }), {
    title: "Title must be at least 4 characters.",
    body: "Investigation note must be at least 12 characters.",
  });
  assert.deepEqual(validateAnalystNote({ title: "Evidence review", body: "Validated the source evidence." }), {});
});

test("trims incident fields before validating length", () => {
  assert.deepEqual(validateIncidentDraft({ title: "   ", summary: "" }), {
    title: "Title is required.",
    summary: "Summary is required.",
  });
  assert.deepEqual(validateIncidentDraft({ title: "  SSH review  ", summary: "  Review affected identities  " }), {});
});

test("normalizes and validates analyst-note tags", () => {
  assert.deepEqual(parseNoteTags(" Identity, identity, Containment "), ["identity", "containment"]);
  assert.equal(validateAnalystNote({
    title: "Valid title",
    body: "Long enough investigation body",
    tags: "one,two,three,four,five,six,seven",
  }).tags, "Use no more than 6 tags.");
  assert.match(validateAnalystNote({
    title: "Valid title",
    body: "Long enough investigation body",
    tags: "x".repeat(41),
  }).tags, /40 characters/);
});

test("requires a nonempty workspace name", () => {
  assert.deepEqual(validateWorkspaceSettings({ workspace: { name: "   " } }), {
    workspaceName: "Workspace name is required.",
  });
  assert.deepEqual(validateWorkspaceSettings({ workspace: { name: "CyberShield" } }), {});
});
