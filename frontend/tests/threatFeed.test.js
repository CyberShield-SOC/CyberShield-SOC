import assert from "node:assert/strict";
import test from "node:test";

import {
  feedImportSummary,
  feedNameFromFilename,
  isStixContent,
  MAX_FEED_FILE_BYTES,
  summarizeStixBundle,
  validateFeedFile,
} from "../src/soc/utils/threatFeed.js";

const indicator = (pattern, extra = {}) => ({ type: "indicator", pattern, pattern_type: "stix", ...extra });
const bundle = (...objects) => JSON.stringify({ type: "bundle", id: "bundle--x", objects });

test("content opening with a brace is treated as STIX, anything else as text", () => {
  assert.equal(isStixContent('﻿\n  {"type":"bundle"}'), true);
  assert.equal(isStixContent("198.51.100.7\n# {comment}"), false);
  assert.equal(isStixContent(""), false);
});

test("feed files are checked for type, emptiness and size", () => {
  assert.equal(validateFeedFile({ name: "feed.stix.json", size: 10 }), "");
  assert.equal(validateFeedFile({ name: "blocklist.TXT", size: 10 }), "");
  assert.match(validateFeedFile({ name: "feed.xml", size: 10 }), /must be \.txt/);
  assert.match(validateFeedFile({ name: "feed.txt", size: 0 }), /empty/);
  assert.match(validateFeedFile({ name: "feed.txt", size: MAX_FEED_FILE_BYTES + 1 }), /10 MB/);
  assert.match(validateFeedFile(null), /Choose a feed file/);
});

test("a feed name is derived from the filename within the server's rules", () => {
  assert.equal(feedNameFromFilename("Abuse CH (2026).stix.json"), "Abuse-CH-2026");
  assert.equal(feedNameFromFilename("spamhaus_drop.txt"), "spamhaus_drop");
  assert.equal(feedNameFromFilename("__lists.csv"), "lists");
  assert.equal(feedNameFromFilename("???.json"), "");
  assert.equal(feedNameFromFilename(`${"a".repeat(140)}.txt`).length, 100);
});

test("the sample-mode STIX summary counts usable and unusable indicators", () => {
  const content = bundle(
    { type: "identity", name: "owner" },
    indicator("[ipv4-addr:value = '198.51.100.7']"),
    indicator("[ipv4-addr:value ISSUBSET '203.0.113.0/24']"),
    indicator("[domain-name:value = 'evil.example.test']"),
    indicator("[file:name = 'dropper.exe']"),
    indicator("[ipv4-addr:value = '198.51.100.8']", { revoked: true }),
    indicator("alert tcp any any", { pattern_type: "snort" }),
  );

  assert.deepEqual(summarizeStixBundle(content), { imported: 3, rejected: 3 });
});

test("JSON that is not a STIX bundle is refused with the server's wording", () => {
  assert.throws(() => summarizeStixBundle("{nope"), /could not be read/);
  assert.throws(() => summarizeStixBundle('{"type":"report","objects":[]}'), /must be a STIX 2\.1 bundle/);
  assert.throws(() => summarizeStixBundle('{"type":"bundle"}'), /must be a STIX 2\.1 bundle/);
});

test("the import summary explains what was skipped, per format", () => {
  assert.equal(
    feedImportSummary({ source: "abuse-ch", imported: 1, rejectedLines: 0, format: "text" }),
    'Imported 1 indicator into "abuse-ch".',
  );
  assert.equal(
    feedImportSummary({ source: "abuse-ch", imported: 12, rejectedLines: 2, format: "text" }),
    'Imported 12 indicators into "abuse-ch". Skipped 2 unrecognized lines.',
  );
  assert.equal(
    feedImportSummary({ source: "isac", imported: 4, rejectedLines: 1, format: "stix" }),
    'Imported 4 indicators from the STIX bundle into "isac". 1 STIX indicator was skipped: only IPs, ranges, and domains can be matched.',
  );
});
