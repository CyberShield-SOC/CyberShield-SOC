import test from "node:test";
import assert from "node:assert/strict";
import { describeIpAddress, summarizeSourceActivity } from "../src/soc/utils/ipLocation.js";

test("classifies local and documentation addresses without false country claims", () => {
  assert.equal(describeIpAddress("10.0.0.5").label, "Private network");
  assert.equal(describeIpAddress("127.0.0.1").label, "Loopback address");
  assert.equal(describeIpAddress("203.0.113.4").label, "Documentation range");
  assert.equal(describeIpAddress("2001:db8::10").label, "Documentation range");
});

test("keeps unknown addresses in top-source counts", () => {
  const sources = summarizeSourceActivity([
    { sourceIp: "Unknown", source: "proxy" },
    { sourceIp: "", source: "proxy" },
    { sourceIp: "10.0.0.5", source: "endpoint" },
  ]);
  assert.equal(sources[0].sourceIp, "Unknown");
  assert.equal(sources[0].count, 2);
  assert.equal(sources[0].location.label, "Unknown location");
});

test("uses supplied country metadata and keeps unknown sources explicit", () => {
  const located = describeIpAddress("8.8.8.8", { countryCode: "US", country: "United States" });
  assert.equal(located.label, "United States");
  assert.equal(located.flag, "🇺🇸");
  assert.equal(describeIpAddress("Unknown").label, "Unknown location");
  assert.equal(describeIpAddress("not-an-ip").type, "unknown");
});
