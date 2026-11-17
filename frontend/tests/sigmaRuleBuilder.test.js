import assert from "node:assert/strict";
import test from "node:test";

import {
  conditionFromApi,
  conditionToApi,
  conditionToDsl,
  describeCondition,
  joinAlternatives,
  splitAlternatives,
  supportsAlternatives,
} from "../src/soc/utils/ruleConditions.js";
import {
  customRuleUpdates,
  formatWindowSeconds,
  validateCustomRuleDraft,
  windowSecondsOf,
  windowValueOf,
} from "../src/soc/utils/customRuleDraft.js";
import {
  normalizeSigmaImport,
  sigmaImportSummary,
  validateSigmaFile,
  validateSigmaText,
} from "../src/soc/utils/sigmaImport.js";

const dslText = (fragments) => fragments.map((fragment) => fragment.text).join("");
const draft = (overrides = {}) => ({
  ruleName: "Rule",
  category: "generic_detection",
  severity: "high",
  groupBy: "none",
  window: "10m",
  conditions: [{ field: "process", operator: "equals", value: "sshd" }],
  ...overrides,
});

test("alternatives split on unescaped pipes and round-trip with escaping", () => {
  assert.deepEqual(splitAlternatives("/bin/bash | /bin/sh"), ["/bin/bash", "/bin/sh"]);
  assert.deepEqual(splitAlternatives("a \\| b | c"), ["a | b", "c"]);
  assert.deepEqual(splitAlternatives("single"), ["single"]);
  assert.deepEqual(splitAlternatives("a || b"), ["a", "", "b"]);
  const values = ["cmd.exe", "a|b"];
  assert.deepEqual(splitAlternatives(joinAlternatives(values)), values);
});

test("only operators that can hold a list offer alternatives", () => {
  assert.equal(supportsAlternatives("string", "endswith"), true);
  assert.equal(supportsAlternatives("string", "in"), false);
  assert.equal(supportsAlternatives("number", "equals"), true);
  assert.equal(supportsAlternatives("number", ">"), false);
  assert.equal(supportsAlternatives("timestamp", "between"), false);
});

test("conditions convert between the API shape and the builder", () => {
  const stored = { field: "command", operator: "endswith", values: ["/bin/bash", "/bin/sh"], negate: true, timezone: null };
  const editable = conditionFromApi(stored);

  assert.deepEqual(editable, { field: "command", operator: "endswith", value: "/bin/bash | /bin/sh", negate: true, timezone: "" });
  assert.deepEqual(conditionToApi(editable, "string"), {
    field: "command", operator: "endswith", timezone: null, values: ["/bin/bash", "/bin/sh"], negate: true,
  });
  // A single value and no NOT keep the original stored shape.
  assert.deepEqual(conditionToApi({ field: "status", operator: "equals", value: "FAILED" }, "string"), {
    field: "status", operator: "equals", timezone: null, value: "FAILED",
  });
  // "in" keeps its comma list as one value.
  assert.deepEqual(conditionToApi({ field: "username", operator: "in", value: "a, b" }, "string").value, "a, b");
});

test("the DSL preview shows NOT, list operators and the new string operators", () => {
  assert.equal(dslText(conditionToDsl({ field: "command", operator: "startswith", value: "/tmp/" }, "string")), 'startswith(command, "/tmp/")');
  assert.equal(
    dslText(conditionToDsl({ field: "command", operator: "endswith", value: "/bin/bash | /bin/sh", negate: true }, "string")),
    'not any_endswith(command, ["/bin/bash", "/bin/sh"])',
  );
  assert.equal(dslText(conditionToDsl({ field: "port", operator: "equals", value: "22 | 2222" }, "number")), "port in [22, 2222]");
  assert.equal(describeCondition({ field: "process", operator: "equals", values: ["a", "b"], negate: true }), "NOT process equals a | b");
});

test("windows accept presets and imported whole-second values", () => {
  assert.equal(windowSecondsOf("10m"), 600);
  assert.equal(windowSecondsOf("120s"), 120);
  assert.equal(windowSecondsOf("59s"), null);
  assert.equal(windowSecondsOf("86401s"), null);
  assert.equal(windowValueOf(1800), "30m");
  assert.equal(windowValueOf(120), "120s");
  assert.equal(formatWindowSeconds(120), "2 minutes");
  assert.equal(formatWindowSeconds(7200), "2 hours");
  assert.equal(formatWindowSeconds(90), "90 seconds");
});

test("draft validation covers alternatives, minimum count and technique", () => {
  assert.deepEqual(validateCustomRuleDraft(draft()).syntaxProblems, []);
  assert.deepEqual(validateCustomRuleDraft(draft({ window: "120s", minCount: "5", mitreTechnique: "t1110.001" })).syntaxProblems, []);
  const problems = (overrides) => validateCustomRuleDraft(draft(overrides)).syntaxProblems;
  assert.match(problems({ conditions: [{ field: "process", operator: "equals", value: "a | | b" }] })[0], /empty alternative/);
  assert.match(problems({ conditions: [{ field: "port", operator: "equals", value: "22 | http" }] })[0], /port numbers/);
  assert.match(problems({ minCount: "0" })[0], /Minimum events/);
  assert.match(problems({ minCount: "2.5" })[0], /Minimum events/);
  assert.match(problems({ mitreTechnique: "TA0006" })[0], /ATT&CK technique/);
  assert.match(problems({ window: "30s" })[0], /time window/);
  assert.deepEqual(validateCustomRuleDraft(draft({ conditions: [{ field: "dns_query", operator: "endswith", value: ".example" }] })).unknownFields, []);
});

test("rule updates send the new rule-level fields", () => {
  assert.deepEqual(customRuleUpdates({ minCount: "5", mitreTechnique: " t1110 " }), { min_count: 5, mitre_technique: "T1110" });
  assert.deepEqual(customRuleUpdates({ mitreTechnique: "" }), { mitre_technique: null });
});

test("Sigma files and text are checked before upload", () => {
  assert.equal(validateSigmaFile({ name: "rules.yml", size: 10 }), "");
  assert.equal(validateSigmaFile({ name: "rules.YAML", size: 10 }), "");
  assert.match(validateSigmaFile({ name: "rules.json", size: 10 }), /\.yml or \.yaml/);
  assert.match(validateSigmaFile({ name: "rules.yml", size: 300_000 }), /256 KB/);
  assert.match(validateSigmaText("   "), /Paste one or more/);
  assert.match(validateSigmaText("title: x\nlevel: high"), /needs a title and a detection/);
  assert.equal(validateSigmaText("title: x\ndetection:\n  sel: {User: a}\n  condition: sel"), "");
});

test("import results are normalised and summarised", () => {
  const result = normalizeSigmaImport({
    results: [
      { title: "A", status: "created", rule_id: "R-120", notes: ["note"], rule: { id: 9 } },
      { title: "B", status: "skipped", rule_id: "R-110", reason: "Already imported as R-110." },
      { title: "C", status: "rejected", reason: "Not imported: OR between selections is not supported." },
      { title: "D", status: "exploded" },
    ],
  }, (rule) => ({ backendId: rule.id }));

  assert.equal(result.results.length, 3);
  assert.deepEqual([result.created, result.skipped, result.rejected], [1, 1, 1]);
  assert.deepEqual(result.results[0].rule, { backendId: 9 });
  assert.equal(sigmaImportSummary(result), "1 imported as a draft, 1 already imported, 1 could not be translated.");
  assert.equal(sigmaImportSummary({ created: 3, skipped: 0, rejected: 0 }), "3 imported as drafts.");
  assert.equal(sigmaImportSummary({ created: 0, skipped: 0, rejected: 0 }), "No rules were found in that YAML.");
});
