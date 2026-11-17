import { useState } from "react";
import { RefreshCw } from "../../icons";
import { useSocWorkspace } from "../context/SocWorkspaceContext";
import { socRepository } from "../services/socRepository";
import { InlineNotice, LoadingState, Panel, StatusBadge } from "./Ui";
import { ENTITY_LABELS } from "../utils/ruleConfig";
import { pilotLabel } from "../utils/mlInsight";

// The live rule setting (edited by Promote/Revert below) wins over the value
// the overview was fetched with, so the row flips as soon as the save lands.
function shadowModeOf(live, row) {
  const value = live?.params?.shadow_mode ?? live?.defaultParams?.shadow_mode;
  return value === undefined ? row.shadowMode : Boolean(value);
}

function readinessStatus(row, shadowMode) {
  if (!row.activeModel) return row.ready ? "pending" : "disabled";
  return shadowMode === false ? "enabled" : "pending";
}

/**
 * Training progress, and the shadow-mode "promote to active" control, for
 * the three behavioral-anomaly pilots. A trained model never alerts on its
 * own (see each rule's own docstring): `params.shadow_mode` defaults on, so
 * every score is logged for review but withheld from Alerts until an Admin
 * or Analyst deliberately turns it off here — this panel is that control.
 */
export function MlModelsPanel({ canAdminister, canManageRules, ruleSettings, onRuleUpdated, icon: Icon }) {
  // The same `mlAnomalies` resource the dashboard panel shows, so training
  // here is visible there after the shared refresh, and vice versa.
  const { mlAnomalies: rows, resources, refresh } = useSocWorkspace();
  const { loading, error } = resources.mlAnomalies;
  const [trainingFeatureSet, setTrainingFeatureSet] = useState(null);
  const [trainError, setTrainError] = useState("");
  const [trainedMessage, setTrainedMessage] = useState("");
  const [shadowBusyFeatureSet, setShadowBusyFeatureSet] = useState(null);
  const [shadowError, setShadowError] = useState("");

  const load = () => refresh("mlAnomalies");

  async function trainModel(featureSet) {
    if (!canAdminister || trainingFeatureSet) return;
    setTrainingFeatureSet(featureSet);
    setTrainError("");
    setTrainedMessage("");
    try {
      const model = await socRepository.trainMlModel(featureSet);
      setTrainedMessage(`${pilotLabel(featureSet)} trained — version ${model.version} is now active.`);
      // The new version has scored nothing yet; re-read rather than patch so
      // scored_count and the ranked scores reset together with active_model.
      await load();
    } catch (trainingError) {
      setTrainError(trainingError.message || "The model could not be trained.");
    } finally {
      setTrainingFeatureSet(null);
    }
  }

  async function setShadowMode(featureSet, engineKey, shadowMode) {
    if (!canManageRules || shadowBusyFeatureSet || !engineKey) return;
    setShadowBusyFeatureSet(featureSet);
    setShadowError("");
    try {
      const updated = await socRepository.updateDetectionRule(engineKey, { params: { shadow_mode: shadowMode } });
      onRuleUpdated?.(updated);
    } catch (updateError) {
      setShadowError(updateError.message || "That rule's shadow-mode setting could not be updated.");
    } finally {
      setShadowBusyFeatureSet(null);
    }
  }

  return (
    <Panel
      title="ML model training"
      subtitle={`${rows.length} behavioral-anomaly pilot${rows.length === 1 ? "" : "s"} · shadow mode`}
      actions={(
        <button className="soc-button secondary compact" type="button" disabled={loading} onClick={load}>
          <RefreshCw size={14} className={loading ? "spin" : ""} aria-hidden="true" />
          Refresh
        </button>
      )}
    >
      {error && <InlineNotice tone="error" title="Readiness error">{error}</InlineNotice>}
      {trainError && <InlineNotice tone="error" title="Training failed" onDismiss={() => setTrainError("")}>{trainError}</InlineNotice>}
      {trainedMessage && <InlineNotice tone="success" title="Training complete" onDismiss={() => setTrainedMessage("")}>{trainedMessage}</InlineNotice>}
      {shadowError && <InlineNotice tone="error" title="Update failed" onDismiss={() => setShadowError("")}>{shadowError}</InlineNotice>}
      {!canAdminister && (
        <InlineNotice tone="info" title="Read-only">Only an Admin can train or retrain a model. Promoting a trained model to active needs an Admin or Analyst.</InlineNotice>
      )}
      {loading ? (
        <LoadingState label="Loading ML training readiness…" />
      ) : (
        <div className="config-list detection-rule-list">
          {rows.map((row) => {
            const needed = Math.max(0, row.minSamples - row.sampleCount);
            const isTraining = trainingFeatureSet === row.featureSet;
            const engineKey = row.ruleName;
            const shadowMode = shadowModeOf(engineKey ? ruleSettings?.[engineKey] : null, row);
            const isShadowBusy = shadowBusyFeatureSet === row.featureSet;
            return (
              <div className="threat-feed-row ml-model-row" key={row.featureSet}>
                <span>
                  <strong>{pilotLabel(row.featureSet)}</strong>
                  <small>
                    Pivots on {ENTITY_LABELS[row.entityType] || row.entityType}
                    {" · "}{row.sampleCount} of {row.minSamples} training samples
                    {row.activeModel
                      ? <> · active v{row.activeModel.version}</>
                      : <> · no model trained yet</>}
                    {row.activeModel && (
                      shadowMode
                        ? <> · shadow mode: scoring silently, not yet alerting</>
                        : <> · promoted: alerts on this rule are live</>
                    )}
                  </small>
                </span>
                <span className="ml-model-row-actions">
                  <StatusBadge status={readinessStatus(row, shadowMode)} />
                  {canAdminister && (
                    <button
                      className="soc-button secondary compact"
                      type="button"
                      disabled={!row.ready || trainingFeatureSet !== null}
                      title={!row.ready ? `Needs ${needed} more sample${needed === 1 ? "" : "s"} before it can train.` : undefined}
                      onClick={() => trainModel(row.featureSet)}
                    >
                      {isTraining ? "Training…" : row.activeModel ? "Retrain" : "Train model"}
                    </button>
                  )}
                  {canManageRules && row.activeModel && engineKey && (
                    <button
                      className="soc-button secondary compact"
                      type="button"
                      disabled={shadowBusyFeatureSet !== null}
                      onClick={() => setShadowMode(row.featureSet, engineKey, !shadowMode)}
                    >
                      {isShadowBusy ? "Saving…" : shadowMode ? "Promote to active" : "Revert to shadow mode"}
                    </button>
                  )}
                </span>
              </div>
            );
          })}
          {!rows.length && (
            <div className="table-empty">
              {Icon && <Icon size={22} />}
              <strong>No ML pilots registered</strong>
              <span>Behavioral-anomaly feature sets will appear here once the backend registers a trainer.</span>
            </div>
          )}
        </div>
      )}
    </Panel>
  );
}
