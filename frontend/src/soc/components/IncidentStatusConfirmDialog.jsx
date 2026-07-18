import { AlertTriangle, CheckCircle2, X } from "lucide-react";
import { incidentTerminalAction } from "../utils/incidentWorkflow";

/**
 * Guards terminal incident transitions so a stray select or button click
 * cannot silently remove an investigation from the active queue.
 */
export default function IncidentStatusConfirmDialog({ disabled, incident, onCancel, onConfirm, status }) {
  const action = incidentTerminalAction(status);
  if (!incident || !action) return null;

  return (
    <div
      className="soc-modal-backdrop"
      role="presentation"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget && !disabled) onCancel();
      }}
    >
      <section
        className="soc-modal confirmation-modal incident-status-confirmation"
        role="alertdialog"
        aria-modal="true"
        aria-labelledby="incident-status-confirmation-title"
        aria-describedby="incident-status-confirmation-description"
      >
        <header>
          <div>
            <h2 id="incident-status-confirmation-title">{action.title}</h2>
            <p id="incident-status-confirmation-description">
              {incident.id} · {incident.title}
            </p>
          </div>
          <button type="button" disabled={disabled} onClick={onCancel} aria-label="Close confirmation">
            <X size={18} />
          </button>
        </header>
        <div className="incident-status-confirmation-message">
          <AlertTriangle size={18} aria-hidden="true" />
          <p>{action.description}</p>
        </div>
        <div className="soc-modal-actions">
          <button className="soc-button secondary" type="button" autoFocus disabled={disabled} onClick={onCancel}>
            Keep investigating
          </button>
          <button className="soc-button danger" type="button" disabled={disabled} onClick={onConfirm}>
            <CheckCircle2 size={15} />
            {disabled ? "Saving…" : action.confirmLabel}
          </button>
        </div>
      </section>
    </div>
  );
}
