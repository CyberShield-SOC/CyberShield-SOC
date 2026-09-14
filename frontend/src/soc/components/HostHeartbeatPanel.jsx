import { useEffect, useState } from "react";
import { RefreshCw, Search } from "lucide-react";
import { socRepository } from "../services/socRepository";
import { InlineNotice, LoadingState, Panel, StatusBadge } from "./Ui";
import { formatTimestamp } from "../utils/eventUtils";

const STATUS_LABELS = Object.freeze({ reporting: "reporting", silent: "silent", learning: "learning" });

function formatDuration(seconds) {
  if (!seconds) return "0m";
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes}m`;
  const hours = Math.floor(minutes / 60);
  return `${hours}h ${minutes % 60}m`;
}

/**
 * Reporting status for every host host_log_silence has seen. Since there's
 * no background scheduler, "Check for silent hosts" is how an ongoing
 * silence (nothing has been uploaded since) gets noticed and alerted.
 */
export function HostHeartbeatPanel({ canWrite, icon: Icon }) {
  const [hosts, setHosts] = useState([]);
  const [checkedAt, setCheckedAt] = useState(null);
  const [loading, setLoading] = useState(true);
  const [checking, setChecking] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState(null);

  async function load() {
    setLoading(true);
    setError("");
    try {
      const data = await socRepository.getHostHeartbeats();
      setHosts(data.hosts);
      setCheckedAt(data.checkedAt);
    } catch (loadError) {
      setError(loadError.message || "Host reporting status could not be loaded.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void load();
  }, []);

  async function runCheck() {
    setChecking(true);
    setError("");
    setResult(null);
    try {
      const alerts = await socRepository.checkHostSilence();
      setResult(alerts.length);
      await load();
    } catch (checkError) {
      setError(checkError.message || "The silence check could not be run.");
    } finally {
      setChecking(false);
    }
  }

  const silentCount = hosts.filter((host) => host.status === "silent").length;

  return (
    <Panel
      title="Host reporting status"
      subtitle={`${hosts.length} host${hosts.length === 1 ? "" : "s"} tracked · used by host_log_silence`}
      actions={canWrite && (
        <button className="soc-button secondary compact" type="button" disabled={checking} onClick={runCheck}>
          <RefreshCw size={14} className={checking ? "spin" : ""} aria-hidden="true" />
          {checking ? "Checking…" : "Check for silent hosts"}
        </button>
      )}
    >
      {error && <InlineNotice tone="error" title="Heartbeat error" onDismiss={() => setError("")}>{error}</InlineNotice>}
      {result !== null && (
        <InlineNotice tone={result > 0 ? "warning" : "success"} title="Check complete" onDismiss={() => setResult(null)}>
          {result > 0 ? `Raised ${result} new silence alert${result === 1 ? "" : "s"}.` : "No newly silent hosts."}
        </InlineNotice>
      )}
      {loading ? (
        <LoadingState label="Loading host reporting status…" />
      ) : (
        <div className="config-list detection-rule-list">
          {hosts.map((host) => (
            <div className="threat-feed-row" key={host.hostname}>
              <span>
                <strong>{host.hostname}</strong>
                <small>
                  {host.eventCount} event{host.eventCount === 1 ? "" : "s"}
                  {host.cadenceSeconds && <> · reports every ~{formatDuration(host.cadenceSeconds)}</>}
                  {" · last seen "}{host.lastSeenAt ? formatTimestamp(host.lastSeenAt) : "never"}
                  {host.status === "silent" && <> · silent for {formatDuration(host.silentForSeconds)}</>}
                </small>
              </span>
              <StatusBadge status={STATUS_LABELS[host.status] || host.status} />
            </div>
          ))}
          {!hosts.length && (
            <div className="table-empty">
              {Icon && <Icon size={22} />}
              <strong>No hosts tracked yet</strong>
              <span>Upload syslog data with a hostname to start tracking reporting cadence.</span>
            </div>
          )}
        </div>
      )}
      {checkedAt && !loading && (
        <p className="threat-feed-checked-at">
          <Search size={12} aria-hidden="true" /> Last checked {formatTimestamp(checkedAt)}
          {silentCount > 0 && ` · ${silentCount} host${silentCount === 1 ? "" : "s"} currently silent`}
        </p>
      )}
    </Panel>
  );
}
