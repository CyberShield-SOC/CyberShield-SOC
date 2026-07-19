const SPREADSHEET_FORMULA_PREFIX = /^[=+\-@]/;

export function filterEvents(events, filters) {
  const query = String(filters.query || "").trim().toLowerCase();

  return events.filter((event) => {
    const haystack = [
      event.id,
      event.source,
      event.sourceIp,
      event.user,
      event.event,
      event.rule,
      event.message,
    ]
      .join(" ")
      .toLowerCase();

    return (
      (!query || haystack.includes(query)) &&
      (!filters.severity || event.severity === filters.severity) &&
      (!filters.status || event.status === filters.status) &&
      (!filters.source || event.source === filters.source)
    );
  });
}

export function formatTimestamp(value) {
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return "Unknown time";

  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  }).format(date);
}

export function escapeCsvCell(value) {
  let safeValue = String(value ?? "").replace(/\r?\n/g, " ");
  if (SPREADSHEET_FORMULA_PREFIX.test(safeValue)) safeValue = `'${safeValue}`;
  return `"${safeValue.replace(/"/g, '""')}"`;
}

export function eventsToCsv(events) {
  const columns = ["id", "timestamp", "source", "sourceIp", "user", "event", "severity", "status", "risk", "rule"];
  return [
    columns.map(escapeCsvCell).join(","),
    ...events.map((event) => columns.map((key) => escapeCsvCell(event[key])).join(",")),
  ].join("\n");
}

export function downloadEventsCsv(events) {
  const blob = new Blob([eventsToCsv(events)], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `cybershield-events-${new Date().toISOString().slice(0, 10)}.csv`;
  link.hidden = true;
  document.body.append(link);
  link.click();
  link.remove();
  // Firefox may not start the download until after the click handler returns.
  window.setTimeout(() => URL.revokeObjectURL(url), 1_000);
}

export function incidentsToCsv(incidents) {
  const columns = ["id", "title", "owner", "priority", "status", "updated", "completedAt", "completedBy", "summary"];
  return [
    columns.map(escapeCsvCell).join(","),
    ...incidents.map((incident) => columns.map((key) => escapeCsvCell(incident[key])).join(",")),
  ].join("\n");
}

export function downloadIncidentsCsv(incidents) {
  const blob = new Blob([incidentsToCsv(incidents)], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `cybershield-incident-history-${new Date().toISOString().slice(0, 10)}.csv`;
  link.hidden = true;
  document.body.append(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1_000);
}

export function validateLogFile(
  file,
  { allowedExtensions = [".log", ".csv", ".json", ".jsonl"], maxBytes = 10 * 1024 * 1024 } = {},
) {
  if (!file || typeof file.name !== "string") {
    throw new Error("Choose a valid log file.");
  }

  const dotIndex = file.name.lastIndexOf(".");
  const extension = dotIndex >= 0 ? file.name.slice(dotIndex).toLowerCase() : "";

  if (!allowedExtensions.includes(extension)) {
    throw new Error(`Choose a ${allowedExtensions.join(", ")} file.`);
  }
  if (!Number.isFinite(file.size) || file.size <= 0) {
    throw new Error("The selected file is empty.");
  }
  if (file.size > maxBytes) {
    const maxMegabytes = Math.max(1, Math.floor(maxBytes / (1024 * 1024)));
    throw new Error(`The file must be ${maxMegabytes} MB or smaller.`);
  }

  return true;
}

export async function inspectLogFile(file) {
  validateLogFile(file);

  const text = await file.text();
  const records = text.split(/\r?\n/).filter((line) => line.trim()).length;
  if (!records) throw new Error("The selected file does not contain any log records.");
  return { name: file.name, records, size: file.size };
}
