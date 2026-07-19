function isPlainObject(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function isStringArray(value) {
  return Array.isArray(value) && value.every((item) => typeof item === "string");
}

function isValidVersion(value) {
  return (
    isPlainObject(value)
    && Number.isInteger(value.version)
    && value.version > 0
    && typeof value.at === "string"
    && typeof value.author === "string"
    && typeof value.summary === "string"
  );
}

function isValidNote(value) {
  const requiredStrings = ["id", "title", "body", "author", "createdAt", "updatedAt", "linkedType", "linkedId"];
  return (
    isPlainObject(value)
    && requiredStrings.every((key) => typeof value[key] === "string")
    && typeof value.pinned === "boolean"
    && typeof value.archived === "boolean"
    && isStringArray(value.tags)
    && Array.isArray(value.versions)
    && value.versions.length > 0
    && value.versions.every(isValidVersion)
  );
}

export function restoreStoredNotes(value, fallback) {
  const source = Array.isArray(value) && value.every(isValidNote) ? value : fallback;
  return structuredClone(source);
}

function hasCompatibleType(value, fallback) {
  if (typeof fallback === "number") return Number.isFinite(value);
  return typeof value === typeof fallback;
}

const ALLOWED_SETTING_VALUES = Object.freeze({
  "workspace.defaultTimeRange": new Set(["1h", "24h", "7d", "30d", "all"]),
  "workspace.density": new Set(["compact", "comfortable", "spacious"]),
  "workspace.textSize": new Set(["small", "standard", "large"]),
});

function hasAllowedSettingValue(section, key, value, fallback) {
  if (!hasCompatibleType(value, fallback)) return false;
  const allowedValues = ALLOWED_SETTING_VALUES[`${section}.${key}`];
  return !allowedValues || allowedValues.has(value);
}

/**
 * Restores only known setting keys whose primitive types match the defaults.
 * This prevents stale or manually edited session data from corrupting forms.
 */
export function restoreStoredSettings(value, defaults) {
  const stored = isPlainObject(value) ? value : {};

  return Object.fromEntries(Object.entries(defaults).map(([section, sectionDefaults]) => {
    const storedSection = isPlainObject(stored[section]) ? stored[section] : {};
    const restoredSection = Object.fromEntries(
      Object.entries(sectionDefaults).map(([key, fallback]) => [
        key,
        hasAllowedSettingValue(section, key, storedSection[key], fallback) ? storedSection[key] : fallback,
      ]),
    );
    return [section, restoredSection];
  }));
}
