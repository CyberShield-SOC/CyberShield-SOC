function ipv4Parts(value) {
  const parts = String(value || "").trim().split(".");
  if (parts.length !== 4 || parts.some((part) => !/^\d{1,3}$/.test(part))) return null;
  const numbers = parts.map(Number);
  return numbers.every((part) => part >= 0 && part <= 255) ? numbers : null;
}

function flagForCountryCode(value) {
  const code = String(value || "").trim().toUpperCase();
  if (!/^[A-Z]{2}$/.test(code)) return "🌐";
  return String.fromCodePoint(...[...code].map((letter) => 127397 + letter.charCodeAt(0)));
}

function suppliedLocation(record) {
  const countryCode = record?.countryCode || record?.country_code || record?.geo?.countryCode || record?.geo?.country_code;
  const country = record?.country || record?.country_name || record?.geo?.country || record?.geo?.country_name;
  if (!countryCode && !country) return null;
  return {
    code: String(countryCode || "").trim().toUpperCase() || "--",
    flag: flagForCountryCode(countryCode),
    label: String(country || countryCode || "Unknown location").trim(),
    type: "country",
  };
}

/**
 * Describes an IP without guessing geolocation. Country data is used only when
 * supplied by trusted telemetry; private, reserved, and unknown addresses get
 * explicit non-country labels and remain countable in source summaries.
 */
export function describeIpAddress(value, record = {}) {
  const ip = String(value || "").trim();
  if (!ip || ip.toLowerCase() === "unknown") {
    return { code: "--", flag: "🌐", label: "Unknown location", type: "unknown" };
  }

  const normalizedIpv6 = ip.toLowerCase();
  if (normalizedIpv6 === "::1") {
    return { code: "LOCAL", flag: "🏢", label: "Loopback address", type: "private" };
  }
  if (normalizedIpv6.startsWith("fc") || normalizedIpv6.startsWith("fd") || normalizedIpv6.startsWith("fe80:")) {
    return { code: "LOCAL", flag: "🏢", label: "Private network", type: "private" };
  }
  if (normalizedIpv6.startsWith("2001:db8:")) {
    return { code: "TEST", flag: "🌐", label: "Documentation range", type: "reserved" };
  }

  const parts = ipv4Parts(ip);
  if (!parts) return { code: "--", flag: "🌐", label: "Unknown location", type: "unknown" };
  const [first, second, third] = parts;
  if (
    first === 10
    || first === 127
    || (first === 169 && second === 254)
    || (first === 172 && second >= 16 && second <= 31)
    || (first === 192 && second === 168)
  ) {
    return { code: "LOCAL", flag: "🏢", label: first === 127 ? "Loopback address" : "Private network", type: "private" };
  }
  if (
    (first === 192 && second === 0 && third === 2)
    || (first === 198 && second === 51 && third === 100)
    || (first === 203 && second === 0 && third === 113)
  ) {
    return { code: "TEST", flag: "🌐", label: "Documentation range", type: "reserved" };
  }

  return suppliedLocation(record)
    || { code: "--", flag: "🌐", label: "Unknown location", type: "unknown" };
}

export function summarizeSourceActivity(events, limit = 5) {
  const sources = new Map();
  (Array.isArray(events) ? events : []).forEach((event) => {
    const sourceIp = String(event?.sourceIp || "Unknown").trim() || "Unknown";
    const location = describeIpAddress(sourceIp, event);
    const current = sources.get(sourceIp) || { count: 0, location, source: event?.source || "Event source" };
    current.count += 1;
    if (current.location.type === "unknown" && location.type !== "unknown") current.location = location;
    sources.set(sourceIp, current);
  });
  return [...sources.entries()]
    .map(([sourceIp, value]) => ({ sourceIp, ...value }))
    .sort((left, right) => right.count - left.count || left.sourceIp.localeCompare(right.sourceIp))
    .slice(0, Math.max(0, Number(limit) || 0));
}
