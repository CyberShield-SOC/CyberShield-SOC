import test from "node:test";
import assert from "node:assert/strict";
import { formatNavigationBadgeCount } from "../src/soc/utils/countFormat.js";

test("keeps sidebar badge counts compact without losing a stable zero state", () => {
  assert.equal(formatNavigationBadgeCount(0), "0");
  assert.equal(formatNavigationBadgeCount(-1), "0");
  assert.equal(formatNavigationBadgeCount("invalid"), "0");
  assert.equal(formatNavigationBadgeCount(1), "1");
  assert.equal(formatNavigationBadgeCount(99), "99");
  assert.equal(formatNavigationBadgeCount(100), "99+");
  assert.equal(formatNavigationBadgeCount(1_000), "99+");
});
