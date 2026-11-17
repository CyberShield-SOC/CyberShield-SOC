import { useEffect, useState } from "react";
import { Download, FileUp, Trash2, Upload, X } from "lucide-react";
import { useSocWorkspace } from "../context/SocWorkspaceContext";
import { socRepository } from "../services/socRepository";
import { InlineNotice, LoadingState, Panel } from "./Ui";
import { formatTimestamp } from "../utils/eventUtils";
import {
  exportThreatFeedStix,
  FEED_FILE_ACCEPT,
  feedImportSummary,
  feedNameFromFilename,
  isStixContent,
  validateFeedFile,
} from "../utils/threatFeed";

const TYPE_LABELS = Object.freeze({ ip: "IPs", cidr: "Ranges", domain: "Domains" });

/**
 * Manage named threat-intelligence feeds for the threat_intel_match rule.
 * A feed is one IP/CIDR/domain per line or a STIX 2.1 bundle, pasted or read
 * from a file; re-importing the same source name replaces that feed's
 * indicators (see backend/app/repositories/threat_intel_repository.py).
 * Any feed can be exported back out as a STIX 2.1 bundle.
 */
export function ThreatIntelPanel({ canWrite, canAdminister, icon: Icon }) {
  const [feeds, setFeeds] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [source, setSource] = useState("");
  const [content, setContent] = useState("");
  const [importing, setImporting] = useState(false);
  const [importResult, setImportResult] = useState(null);
  // A chosen file is held here rather than in the textarea: a 10 MB bundle
  // is fine to send but not to render in an editable field.
  const [feedFile, setFeedFile] = useState(null);
  const [exportingSource, setExportingSource] = useState("");
  const { repositoryMode } = useSocWorkspace();
  const feedContent = feedFile ? feedFile.content : content;
  const exportBlocked = repositoryMode !== "api"
    ? "STIX export runs on the server, so it is unavailable with sample data."
    : "";

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
    if (!source.trim() || !feedContent.trim() || importing) return;
    setImporting(true);
    setError("");
    setImportResult(null);
    try {
      const result = await socRepository.importThreatIntelFeed({ source: source.trim(), content: feedContent });
      setImportResult(result);
      setContent("");
      setFeedFile(null);
      await load();
    } catch (importError) {
      setError(importError.message || "That feed could not be imported.");
    } finally {
      setImporting(false);
    }
  }

  async function chooseFeedFile(event) {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;
    const problem = validateFeedFile(file);
    if (problem) {
      setError(problem);
      return;
    }
    setError("");
    try {
      const text = await file.text();
      setFeedFile({ name: file.name, size: file.size, content: text });
      if (!source.trim()) setSource(feedNameFromFilename(file.name));
    } catch {
      setError("That file could not be read.");
    }
  }

  async function exportFeed(feedSource) {
    setError("");
    setExportingSource(feedSource);
    try {
      await exportThreatFeedStix(feedSource);
    } catch (exportError) {
      setError(exportError.message || "That feed could not be exported.");
    } finally {
      setExportingSource("");
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
              <span className="threat-feed-actions">
                {canWrite && (
                  <button
                    className="soc-button secondary compact"
                    type="button"
                    onClick={() => exportFeed(feed.source)}
                    disabled={Boolean(exportBlocked) || exportingSource === feed.source}
                    title={exportBlocked || "Download this feed as a STIX 2.1 bundle."}
                  >
                    <Download size={14} aria-hidden="true" /> {exportingSource === feed.source ? "Exporting…" : "Export STIX"}
                  </button>
                )}
                {canAdminister && (
                  <button className="soc-button danger compact" type="button" onClick={() => removeFeed(feed.source)}>
                    <Trash2 size={14} aria-hidden="true" /> Remove
                  </button>
                )}
              </span>
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
      {canWrite && !canAdminister && Boolean(feeds.length) && (
        <InlineNotice tone="info" title="Removal is Admin-only">
          Only an Admin can remove an imported feed. Re-import a feed by its existing name to replace its indicators.
        </InlineNotice>
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
          {feedFile ? (
            <div className="threat-feed-file">
              <span>
                <strong>{feedFile.name}</strong>
                <small>
                  {(feedFile.size / 1024).toFixed(feedFile.size < 10240 ? 1 : 0)} KB · {isStixContent(feedFile.content) ? "STIX 2.1 bundle" : "plain-text list"}
                </small>
              </span>
              <button className="soc-icon-button" type="button" onClick={() => setFeedFile(null)} aria-label={`Remove ${feedFile.name}`}>
                <X size={14} aria-hidden="true" />
              </button>
            </div>
          ) : (
            <label>
              <span>Indicators: one IP, CIDR, or domain per line, or a STIX 2.1 bundle</span>
              <textarea
                rows={5}
                value={content}
                onChange={(event) => setContent(event.target.value)}
                placeholder={"185.220.101.45\n45.155.205.0/24\nbadactor-c2.com"}
                required
              />
              {isStixContent(content) && <small className="threat-feed-format">Reading this as a STIX 2.1 bundle.</small>}
            </label>
          )}
          <div className="rule-threshold-form-actions threat-feed-import-actions">
            <label className={`soc-button secondary compact file-button${importing ? " disabled" : ""}`}>
              <FileUp size={14} aria-hidden="true" /> {feedFile ? "Choose another file" : "Load from file"}
              <input type="file" accept={FEED_FILE_ACCEPT} onChange={chooseFeedFile} disabled={importing} />
            </label>
            <button className="soc-button primary compact" type="submit" disabled={importing}>
              <Upload size={14} aria-hidden="true" /> {importing ? "Importing…" : "Import feed"}
            </button>
          </div>
        </form>
      )}
      {importResult && (
        <InlineNotice tone="success" title="Feed imported" onDismiss={() => setImportResult(null)}>
          {feedImportSummary(importResult)}
        </InlineNotice>
      )}
    </Panel>
  );
}
