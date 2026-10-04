import test from "node:test";
import assert from "node:assert/strict";
import {
  ASSISTANT_MAX_MESSAGES,
  ASSISTANT_MAX_MESSAGE_CHARS,
  assistantToolLabel,
  buildAssistantHistory,
} from "../src/soc/utils/assistantChat.js";
import { timeRangeToHours } from "../src/soc/utils/timeRange.js";
import { assistantErrorMessage, normalizeAssistantReply } from "../src/soc/services/socRepository.js";

const user = (body) => ({ id: body, role: "user", body });
const assistant = (body) => ({ id: body, role: "assistant", body });

test("omits the local welcome message and empty turns from the conversation", () => {
  const history = buildAssistantHistory([
    { id: "welcome", role: "assistant", local: true, body: "Hello!" },
    user("Any brute force?"),
    assistant("   "),
  ]);
  assert.deepEqual(history, [{ role: "user", content: "Any brute force?" }]);
});

test("keeps only the most recent window and starts on a user turn", () => {
  const turns = Array.from({ length: ASSISTANT_MAX_MESSAGES + 5 }, (_, i) => (i % 2 === 0 ? user(`q${i}`) : assistant(`a${i}`)));
  const history = buildAssistantHistory(turns);
  assert.ok(history.length <= ASSISTANT_MAX_MESSAGES);
  assert.equal(history[0].role, "user");
  assert.equal(history.at(-1).content, turns.at(-1).body);
});

test("truncates over-long messages to the API limit", () => {
  const [turn] = buildAssistantHistory([user("x".repeat(ASSISTANT_MAX_MESSAGE_CHARS + 50))]);
  assert.equal(turn.content.length, ASSISTANT_MAX_MESSAGE_CHARS);
});

test("maps the workspace time range to API hours, capping 'all' at 90 days", () => {
  assert.equal(timeRangeToHours("1h"), 1);
  assert.equal(timeRangeToHours("24h"), 24);
  assert.equal(timeRangeToHours("7d"), 168);
  assert.equal(timeRangeToHours("30d"), 720);
  assert.equal(timeRangeToHours("all"), 2160);
  assert.equal(timeRangeToHours("bogus"), 24);
});

test("labels data sources without exposing raw tool names", () => {
  assert.equal(assistantToolLabel("auth_activity"), "Authentication activity");
  assert.equal(assistantToolLabel("something_new"), "Workspace data");
});

test("explains assistant-specific failures and defers to the shared messages otherwise", () => {
  assert.match(assistantErrorMessage(503), /not configured/);
  assert.match(assistantErrorMessage(429), /busy/);
  assert.match(assistantErrorMessage(502), /unavailable/);
  assert.equal(assistantErrorMessage(403), "Your account does not have permission for this action.");
});

test("normalizes the assistant reply and rejects malformed payloads", () => {
  assert.deepEqual(
    normalizeAssistantReply({ reply: "Hi", tools_used: [{ name: "list_alerts", ok: false }, { bad: true }] }),
    { reply: "Hi", toolsUsed: [{ name: "list_alerts", ok: false }] },
  );
  assert.throws(() => normalizeAssistantReply({ reply: "  " }), /invalid response/);
  assert.throws(() => normalizeAssistantReply(null), /invalid response/);
});
