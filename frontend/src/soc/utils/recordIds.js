/**
 * Returns the next numeric identifier without relying on array length or time.
 * Existing malformed identifiers are ignored so imported backend data cannot
 * make the sequence regress or produce a duplicate.
 */
export function nextSequentialId(records, prefix, minimum = 1, padding = 4) {
  const highest = records.reduce((currentHighest, record) => {
    const id = String(record?.id || "");
    if (!id.startsWith(prefix)) return currentHighest;

    const numericPart = id.slice(prefix.length);
    if (!/^\d+$/.test(numericPart)) return currentHighest;
    const numericValue = Number(numericPart);
    if (!Number.isSafeInteger(numericValue)) return currentHighest;
    return Math.max(currentHighest, numericValue);
  }, minimum - 1);

  return `${prefix}${String(highest + 1).padStart(padding, "0")}`;
}

export function nextIncidentId(incidents) {
  return nextSequentialId(incidents, "INC-", 1000, 4);
}
