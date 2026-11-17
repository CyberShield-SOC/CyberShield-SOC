import { useEffect, useRef, useState } from "react";
import { FileUp, Upload, X } from "../../icons";
import { socRepository } from "../services/socRepository";
import {
  SIGMA_FILE_ACCEPT,
  sigmaImportSummary,
  validateSigmaFile,
  validateSigmaText,
} from "../utils/sigmaImport";
import { InlineNotice, ValidationMessage } from "./Ui";

const STATUS_LABELS = Object.freeze({ created: "Draft created", skipped: "Already imported", rejected: "Not imported" });

/**
 * Paste or load Sigma YAML, send it to the server for translation, and show
 * what happened to every rule. Imported rules are drafts: the analyst opens
 * each one, dry-runs it, and enables it.
 */
export function SigmaImportDialog({ onClose, onImported, onReview, repositoryMode }) {
  const [content, setContent] = useState("");
  const [fileName, setFileName] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState(null);
  const textareaRef = useRef(null);
  const sampleMode = repositoryMode !== "api";

  useEffect(() => {
    textareaRef.current?.focus();
    function closeOnEscape(event) {
      if (event.key === "Escape" && !busy) onClose();
    }
    window.addEventListener("keydown", closeOnEscape);
    return () => window.removeEventListener("keydown", closeOnEscape);
  }, [busy, onClose]);

  async function chooseFile(event) {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;
    const problem = validateSigmaFile(file);
    if (problem) {
      setError(problem);
      return;
    }
    try {
      setContent(await file.text());
      setFileName(file.name);
      setError("");
      setResult(null);
    } catch {
      setError("That file could not be read.");
    }
  }

  async function submit(event) {
    event.preventDefault();
    const problem = validateSigmaText(content);
    if (problem) {
      setError(problem);
      textareaRef.current?.focus();
      return;
    }
    setBusy(true);
    setError("");
    try {
      const imported = await socRepository.importSigmaRules(content);
      setResult(imported);
      if (imported.created) onImported?.(imported);
    } catch (importError) {
      setError(importError.message || "The Sigma rules could not be imported.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="soc-modal-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget && !busy) onClose(); }}>
      <section className="soc-modal sigma-import-modal" role="dialog" aria-modal="true" aria-labelledby="sigma-import-title" aria-describedby="sigma-import-description">
        <header>
          <div>
            <h2 id="sigma-import-title">Import Sigma rules</h2>
            <p id="sigma-import-description">
              Each rule becomes a draft custom rule. Rules that need something the engine cannot express exactly,
              such as a regular expression or an OR between selections, are listed with the reason instead.
            </p>
          </div>
          <button type="button" disabled={busy} onClick={onClose} aria-label="Close"><X size={18} /></button>
        </header>

        {sampleMode && (
          <InlineNotice tone="info" title="Sample data">
            Translation runs on the server, so importing is unavailable with sample data. You can still review this form.
          </InlineNotice>
        )}

        {!result ? (
          <form className="sigma-import-form" onSubmit={submit} noValidate>
            <label htmlFor="sigma-import-yaml">
              <span>{fileName ? `YAML from ${fileName}` : "Sigma YAML (separate several rules with ---)"}</span>
              <textarea
                ref={textareaRef}
                id="sigma-import-yaml"
                rows={12}
                spellCheck="false"
                value={content}
                disabled={busy}
                aria-invalid={Boolean(error)}
                aria-describedby={error ? "sigma-import-error" : undefined}
                placeholder={"title: Repeated SSH failures\ndetection:\n    selection:\n        process: sshd\n        message|contains: 'Failed password'\n    timeframe: 1m\n    condition: selection | count() by SourceIp > 4\nlevel: high"}
                onChange={(event) => { setContent(event.target.value); setFileName(""); setError(""); }}
              />
            </label>
            <ValidationMessage id="sigma-import-error">{error}</ValidationMessage>
            <div className="soc-modal-actions">
              <label className={`soc-button secondary file-button${busy ? " disabled" : ""}`}>
                <FileUp size={15} aria-hidden="true" /> Load .yml file
                <input type="file" accept={SIGMA_FILE_ACCEPT} disabled={busy} onChange={chooseFile} />
              </label>
              <button className="soc-button primary" type="submit" disabled={busy || sampleMode} title={sampleMode ? "Connect the backend to import Sigma rules." : undefined}>
                <Upload size={15} aria-hidden="true" /> {busy ? "Importing…" : "Import rules"}
              </button>
            </div>
          </form>
        ) : (
          <div className="sigma-import-results" role="status" aria-live="polite">
            <p className="sigma-import-summary">{sigmaImportSummary(result)}</p>
            <ul>
              {result.results.map((item, index) => (
                <li key={`${item.title}-${index}`} data-status={item.status}>
                  <div>
                    <strong>{item.title}</strong>
                    <span className="sigma-import-status">{STATUS_LABELS[item.status]}{item.ruleId ? ` · ${item.ruleId}` : ""}</span>
                  </div>
                  {item.reason && <p>{item.reason}</p>}
                  {item.notes.map((note) => <p key={note} className="sigma-import-note">{note}</p>)}
                  {item.status === "created" && item.rule && (
                    <button className="soc-text-button" type="button" onClick={() => onReview(item.rule)}>
                      Review and test {item.ruleId}
                    </button>
                  )}
                </li>
              ))}
            </ul>
            <div className="soc-modal-actions">
              <button className="soc-button secondary" type="button" onClick={() => { setResult(null); setContent(""); setFileName(""); }}>Import more</button>
              <button className="soc-button primary" type="button" onClick={onClose}>Done</button>
            </div>
          </div>
        )}
      </section>
    </div>
  );
}
