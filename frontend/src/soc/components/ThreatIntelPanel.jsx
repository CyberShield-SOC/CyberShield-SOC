import { useEffect, useState } from "react";
import { Trash2, Upload } from "lucide-react";
import { socRepository } from "../services/socRepository";
import { InlineNotice, LoadingState, Panel } from "./Ui";
import { formatTimestamp } from "../utils/eventUtils";

const TYPE_LABELS = Object.freeze({ ip: "IPs", cidr: "Ranges", domain: "Domains" });

/**
 * Manage named threat-intelligence feeds for the threat_intel_match rule.
 * One IP/CIDR/domain per line; re-importing the same source name replaces
 * that feed's indicators (see backend/app/repositories/threat_intel_repository.py).
 */
export function ThreatIntelPanel({ canWrite, icon: Icon }) {
  const [feeds, setFeeds] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [source, setSource] = useState("");
  const [content, setContent] = useState("");
  const [importing, setImporting] = useState(false);
  const [importResult, setImportResult] = useState(null);

  async function load() {
    setLoading(true);
    setError("");
    try {
      setFeeds(await socRepository.getThreatIntelFeeds());
    } catch (loadError) {
      setError(loadError.message || "Threat-intel feeds could not be loaded.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void load();
  }, []);

  async function submitImport(event) {
    event.preventDefault();
    if (!source.trim() || !content.trim() || importing) return;
    setImporting(true);
    setError("");
    setImportResult(null);
    try {
      const result = await socRepository.importThreatIntelFeed({ source: source.trim(), content });
      setImportResult(result);
      setContent("");
      await load();
    } catch (importError) {
      setError(importError.message || "That feed could not be imported.");
    } finally {
      setImporting(false);
    }
  }

  async function removeFeed(feedSource) {
    setError("");
    try {
      await socRepository.deleteThreatIntelFeed(feedSource);
      await load();
    } catch (deleteError) {
      setError(deleteError.message || "That feed could not be removed.");
    }
  }

  return (
    <Panel
      title="Threat intelligence feeds"
      subtitle={`${feeds.length} feed${feeds.length === 1 ? "" : "s"} · used by threat_intel_match`}
    >
      {error && <InlineNotice tone="error" title="Feed error" onDismiss={() => setError("")}>{error}</InlineNotice>}
      {loading ? (
        <LoadingState label="Loading threat-intel feeds…" />
      ) : (
        <div className="config-list detection-rule-list threat-feed-list">
          {feeds.map((feed) => (
            <div className="threat-feed-row" key={feed.source}>
              <span>
                <strong>{feed.source}</strong>
                <small>
                  {feed.indicatorCount} indicator{feed.indicatorCount === 1 ? "" : "s"}
                  {Object.entries(feed.byType).some(([, count]) => count) && (
                    <> · {Object.entries(feed.byType).filter(([, count]) => count).map(([type, count]) => `${count} ${TYPE_LABELS[type] || type}`).join(", ")}</>
                  )}
                  {feed.updatedAt && <> · updated {formatTimestamp(feed.updatedAt)}</>}
                </small>
              </span>
              {canWrite && (
                <button className="soc-button danger compact" type="button" onClick={() => removeFeed(feed.source)}>
                  <Trash2 size={14} aria-hidden="true" /> Remove
                </button>
              )}
            </div>
          ))}
          {!feeds.length && (
            <div className="table-empty">
              {Icon && <Icon size={22} />}
              <strong>No feeds imported</strong>
              <span>Import a feed below to enable threat_intel_match.</span>
            </div>
          )}
        </div>
      )}

      {canWrite && (
        <form className="threat-feed-import-form" onSubmit={submitImport}>
          <label>
            <span>Feed name</span>
            <input
              type="text"
              maxLength={100}
              value={source}
              onChange={(event) => setSource(event.target.value)}
              placeholder="e.g. abuse-ch"
              required
            />
          </label>
          <label>
            <span>Indicators (one IP, CIDR, or domain per line)</span>
            <textarea
              rows={5}
              value={content}
              onChange={(event) => setContent(event.target.value)}
              placeholder={"185.220.101.45\n45.155.205.0/24\nbadactor-c2.com"}
              required
            />
          </label>
          <div className="rule-threshold-form-actions">
            <button className="soc-button primary compact" type="submit" disabled={importing}>
              <Upload size={14} aria-hidden="true" /> {importing ? "Importing…" : "Import feed"}
            </button>
          </div>
        </form>
      )}
      {importResult && (
        <InlineNotice tone="success" title="Feed imported" onDismiss={() => setImportResult(null)}>
          Imported {importResult.imported} indicator{importResult.imported === 1 ? "" : "s"} into "{importResult.source}"
          {importResult.rejectedLines ? `; skipped ${importResult.rejectedLines} unrecognized line(s).` : "."}
        </InlineNotice>
      )}
    </Panel>
  );
}
