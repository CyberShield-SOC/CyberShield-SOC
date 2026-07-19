import test from "node:test";
import assert from "node:assert/strict";
import {
  searchShortcutLabel,
  shouldFocusGlobalSearch,
} from "../src/soc/utils/searchShortcuts.js";

test("recognizes global search keyboard shortcuts", () => {
  assert.equal(shouldFocusGlobalSearch({ key: "k", ctrlKey: true }), true);
  assert.equal(shouldFocusGlobalSearch({ key: "K", metaKey: true }), true);
  assert.equal(shouldFocusGlobalSearch({ key: "/", target: { tagName: "BODY" } }), true);
});

test("does not hijack ordinary typing or repeated shortcuts", () => {
  assert.equal(shouldFocusGlobalSearch({ key: "/", target: { tagName: "INPUT" } }), false);
  assert.equal(shouldFocusGlobalSearch({ key: "k", ctrlKey: false }), false);
  assert.equal(shouldFocusGlobalSearch({ key: "k", ctrlKey: true, repeat: true }), false);
  assert.equal(shouldFocusGlobalSearch({ key: "k", ctrlKey: true, altKey: true }), false);
});

test("uses a platform-appropriate visible shortcut label", () => {
  assert.equal(searchShortcutLabel("MacIntel"), "⌘ K");
  assert.equal(searchShortcutLabel("Win32"), "Ctrl K");
});
