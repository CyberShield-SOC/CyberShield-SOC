export function deriveTelemetryReadiness(events, now = Date.now()) {
  const records = Array.isArray(events) ? events : [];
  const ingestionTimes = records
    .map((event) => new Date(event?.ingestedAt || event?.timestamp).getTime())
    .filter(Number.isFinite);
  // Avoid spreading large telemetry arrays into Math.max; browser argument
  // limits vary and real SIEM imports can contain hundreds of thousands rows.
  const latestIngestion = ingestionTimes.reduce(
    (latest, timestamp) => latest === null || timestamp > latest ? timestamp : latest,
    null,
  );
  const ingestionAgeMinutes = latestIngestion === null
    ? null
    : Math.max(0, Math.floor((now - latestIngestion) / 60_000));

  const state = latestIngestion === null || ingestionAgeMinutes > 60
    ? { label: latestIngestion === null ? "No telemetry" : "Stale", tone: latestIngestion === null ? "critical" : "warning" }
    : ingestionAgeMinutes > 15
      ? { label: "Delayed", tone: "warning" }
      : { label: "Live", tone: "healthy" };

  return {
    state,
    latestIngestion,
    ingestionAgeMinutes,
    activeSources: new Set(records.map((event) => event?.source).filter(Boolean)).size,
    failedOutcomes: records.filter((event) => String(event?.status).toLowerCase() === "failed").length,
  };
}

export function deriveAnalystWorkload(activeAlerts, openIncidents) {
  const alerts = Array.isArray(activeAlerts) ? activeAlerts : [];
  const incidents = Array.isArray(openIncidents) ? openIncidents : [];
  const criticalActiveAlerts = alerts.filter((alert) => String(alert?.severity).toLowerCase() === "critical").length;
  const unassignedAlerts = alerts.filter((alert) => {
    const assignee = String(alert?.assignee || "").trim().toLowerCase();
    return !assignee || assignee === "unassigned";
  }).length;
  const escalatedAlerts = alerts.filter((alert) => String(alert?.status).toLowerCase() === "escalated").length;
  const investigatingIncidents = incidents.filter((incident) => String(incident?.status).toLowerCase() === "investigating").length;
  const state = criticalActiveAlerts
    ? { label: "Critical attention", tone: "critical" }
    : unassignedAlerts
      ? { label: "Assignment gap", tone: "warning" }
      : { label: "Balanced", tone: "healthy" };

  return {
    state,
    criticalActiveAlerts,
    unassignedAlerts,
    escalatedAlerts,
    investigatingIncidents,
  };
}

const SEVERITY_RANK = Object.freeze({ critical: 4, high: 3, medium: 2, low: 1, info: 0 });

function cleanText(value) {
  return String(value || "").trim();
}

function alertEvidenceCount(alert) {
  const linkedCount = Array.isArray(alert?.evidenceIds) && alert.evidenceIds.length
    ? alert.evidenceIds.length
    : Array.isArray(alert?.relatedLogEvidence) && alert.relatedLogEvidence.length
      ? alert.relatedLogEvidence.length
      : Math.max(0, Number(alert?.evidenceCount) || 0);
  if (linkedCount) return linkedCount;

  // Some Sprint 1 alert responses contain the rule's normalized count only in
  // the server-authored description. Preserve that evidence count instead of
  // showing a contradictory zero in the dashboard summary.
  const description = cleanText(alert?.reason || alert?.summary || alert?.title);
  const countMatch = description.match(/\b(\d+)\s+[^.]{0,48}\b(?:failures?|attempts?)\b/i);
  return countMatch ? Number(countMatch[1]) : 0;
}

function threatFromAlert(alert) {
  const evidenceCount = alertEvidenceCount(alert);
  const windowSeconds = Math.max(0, Number(alert?.timeWindowSeconds) || 0);
  const user = cleanText(alert?.user) || "Unknown";
  const reason = cleanText(alert?.reason || alert?.summary || alert?.title) || "A security rule requires analyst review.";
  const context = [alert?.title, alert?.ruleName, alert?.ruleId, alert?.reason, alert?.summary]
    .map(cleanText)
    .join(" ")
    .toLowerCase();
  const isSudoPattern = /sudo|privilege escalation/.test(context);

  let title = reason;
  let description = "Review the matched evidence and confirm whether containment is required.";
  let category = "Prioritized detection";

  if (isSudoPattern) {
    category = "Privilege escalation";
    if (evidenceCount >= 3 && windowSeconds > 0 && user !== "Unknown") {
      title = `Repeated sudo failures for '${user}': ${evidenceCount} failures in ${windowSeconds}s.`;
    }
    description = /possible privilege escalation/i.test(title)
      ? "Correlate the account, source, and host activity before containment."
      : "Possible privilege escalation attempt. Correlate the account, source, and host activity before containment.";
  }

  return {
    state: "detected",
    category,
    title,
    description,
    severity: cleanText(alert?.severity).toLowerCase() || "info",
    user,
    sourceIp: cleanText(alert?.sourceIp) || "Unknown",
    ruleId: cleanText(alert?.ruleId) || "Unassigned",
    evidenceCount,
    windowLabel: windowSeconds > 0 ? `${windowSeconds}s` : "Observed event",
    alertId: cleanText(alert?.id) || null,
  };
}

/**
 * Selects one evidence-backed finding for the dashboard. Sudo/privilege
 * escalation patterns take precedence, followed by the highest-risk active
 * alert and then an observed repeated-failure pattern in raw events.
 */
export function deriveThreatAnalysis(alerts, events) {
  const activeAlerts = (Array.isArray(alerts) ? alerts : [])
    .filter((alert) => !["closed", "contained", "resolved", "false positive"].includes(cleanText(alert?.status).toLowerCase()))
    .sort((left, right) => {
      const riskDelta = (Number(right?.risk) || 0) - (Number(left?.risk) || 0);
      return riskDelta || (SEVERITY_RANK[cleanText(right?.severity).toLowerCase()] || 0) - (SEVERITY_RANK[cleanText(left?.severity).toLowerCase()] || 0);
    });
  const sudoAlert = activeAlerts.find((alert) => /sudo|privilege escalation/i.test(
    [alert?.title, alert?.ruleName, alert?.ruleId, alert?.reason, alert?.summary].map(cleanText).join(" "),
  ));
  if (sudoAlert) return threatFromAlert(sudoAlert);
  if (activeAlerts.length) return threatFromAlert(activeAlerts[0]);

  const failuresByUser = new Map();
  (Array.isArray(events) ? events : []).forEach((event) => {
    const user = cleanText(event?.user);
    if (!user || user.toLowerCase() === "unknown" || cleanText(event?.status).toLowerCase() !== "failed") return;
    if (!failuresByUser.has(user)) failuresByUser.set(user, []);
    failuresByUser.get(user).push(event);
  });
  const repeatedFailures = [...failuresByUser.entries()]
    .filter(([, records]) => records.length >= 3)
    .sort((left, right) => right[1].length - left[1].length)[0];

  if (repeatedFailures) {
    const [user, records] = repeatedFailures;
    const timestamps = records
      .map((event) => new Date(event?.timestamp || event?.ingestedAt).getTime())
      .filter(Number.isFinite)
      .sort((left, right) => left - right);
    const windowSeconds = timestamps.length > 1
      ? Math.max(1, Math.round((timestamps.at(-1) - timestamps[0]) / 1000))
      : 0;
    const sourceIp = cleanText(records.find((event) => event?.sourceIp)?.sourceIp) || "Unknown";
    return {
      state: "detected",
      category: "Behavioral correlation",
      title: `Repeated authentication failures for '${user}': ${records.length} failures${windowSeconds ? ` in ${windowSeconds}s` : ""}.`,
      description: "Possible credential attack. Review the account, source, and recent successful authentication activity.",
      severity: "high",
      user,
      sourceIp,
      ruleId: "Behavioral correlation",
      evidenceCount: records.length,
      windowLabel: windowSeconds ? `${windowSeconds}s` : "Selected period",
      alertId: null,
    };
  }

  return {
    state: "clear",
    category: "Continuous monitoring",
    title: "No prioritized threat pattern is active in this time range.",
    description: "CyberShield will surface the highest-priority evidence correlation here when a detection requires review.",
    severity: "info",
    user: "None",
    sourceIp: "None",
    ruleId: "No active rule",
    evidenceCount: 0,
    windowLabel: "Selected period",
    alertId: null,
  };
}
