export const RULE_CATEGORIES = Object.freeze([
  Object.freeze({
    value: "generic_detection",
    label: "Generic Detection",
    shortLabel: "Generic",
    description: "Production-ready rules that inspect normalized events and generate alerts when their criteria match.",
  }),
  Object.freeze({
    value: "threat_hunting",
    label: "Threat Hunting",
    shortLabel: "Hunting",
    description: "Hypothesis-led queries analysts can use to proactively investigate suspicious behavior.",
  }),
  Object.freeze({
    value: "emerging_threat",
    label: "Emerging Threat",
    shortLabel: "Emerging",
    description: "Templates for rapidly evolving indicators, campaigns, and adversary techniques that still require validation.",
  }),
  Object.freeze({
    value: "compliance",
    label: "Compliance",
    shortLabel: "Compliance",
    description: "Audit-oriented checks that help monitor control requirements and privileged activity.",
  }),
  Object.freeze({
    value: "placeholder",
    label: "Placeholder",
    shortLabel: "Placeholder",
    description: "Reserved definitions for detections that have not yet been designed or implemented.",
  }),
]);

export const RULE_CATEGORY_VALUES = Object.freeze(
  RULE_CATEGORIES.map((category) => category.value),
);

const RULE_CATEGORY_LOOKUP = Object.freeze(
  Object.fromEntries(RULE_CATEGORIES.map((category) => [category.value, category])),
);

export function getRuleCategory(value) {
  return RULE_CATEGORY_LOOKUP[value] || RULE_CATEGORY_LOOKUP.generic_detection;
}

export function isRuleCategory(value) {
  return Object.hasOwn(RULE_CATEGORY_LOOKUP, value);
}
