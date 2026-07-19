import test from "node:test";
import assert from "node:assert/strict";
import { restoreStoredNotes, restoreStoredSettings } from "../src/soc/utils/storageValidation.js";

const fallbackNotes = [{
  id: "NOTE-1",
  title: "Review",
  body: "Review evidence",
  author: "Analyst",
  createdAt: "2026-07-16T12:00:00Z",
  updatedAt: "2026-07-16T12:00:00Z",
  tags: ["review"],
  linkedType: "workspace",
  linkedId: "SOC-DAY",
  pinned: false,
  archived: false,
  versions: [{ version: 1, at: "2026-07-16T12:00:00Z", author: "Analyst", summary: "Created" }],
}];

test("accepts well-formed stored notes and clones the result", () => {
  const restored = restoreStoredNotes(fallbackNotes, []);
  assert.deepEqual(restored, fallbackNotes);
  assert.notEqual(restored, fallbackNotes);
});

test("falls back when stored notes have an unsafe shape", () => {
  assert.deepEqual(restoreStoredNotes([{ id: "NOTE-broken", tags: "not-an-array" }], fallbackNotes), fallbackNotes);
  assert.deepEqual(restoreStoredNotes("invalid", fallbackNotes), fallbackNotes);
});

test("restores only known settings with compatible types", () => {
  const defaults = {
    workspace: { name: "SOC", density: "comfortable" },
    security: { sessionMinutes: 30, requireMfa: true },
  };
  const restored = restoreStoredSettings({
    workspace: { name: "Night shift", density: false, unknown: "ignored" },
    security: { sessionMinutes: "forever", requireMfa: false },
    injected: { enabled: true },
  }, defaults);

  assert.deepEqual(restored, {
    workspace: { name: "Night shift", density: "comfortable" },
    security: { sessionMinutes: 30, requireMfa: false },
  });
});

test("rejects unsupported appearance values while preserving valid preferences", () => {
  const defaults = {
    workspace: {
      density: "comfortable",
      textSize: "standard",
      reduceMotion: false,
    },
  };

  assert.deepEqual(restoreStoredSettings({
    workspace: {
      density: "microscopic",
      textSize: "large",
      reduceMotion: true,
    },
  }, defaults), {
    workspace: {
      density: "comfortable",
      textSize: "large",
      reduceMotion: true,
    },
  });
});
