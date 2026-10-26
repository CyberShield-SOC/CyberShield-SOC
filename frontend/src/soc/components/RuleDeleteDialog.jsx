import { useEffect, useRef } from "react";
import { Trash2 } from "lucide-react";

export default function RuleDeleteDialog({ rule, busy, error, onCancel, onConfirm }) {
  const dialog = useRef(null);
  useEffect(() => { dialog.current?.showModal(); }, []);
  return <dialog ref={dialog} className="soc-modal rule-delete-dialog" aria-labelledby="delete-rule-title" onCancel={(event) => { event.preventDefault(); if (!busy) onCancel(); }}>
    <header><div><h2 id="delete-rule-title">Delete custom rule?</h2><p>{rule.id} · {rule.name}</p></div></header>
    <p>This permanently removes the rule from the library. Existing alerts and their evidence are retained.</p>
    {error && <p role="alert">{error}</p>}
    <div className="soc-modal-actions">
      <button className="soc-button secondary" type="button" disabled={busy} onClick={onCancel} autoFocus>Cancel</button>
      <button className="soc-button danger" type="button" disabled={busy} onClick={onConfirm}><Trash2 size={15} />{busy ? "Deleting…" : "Delete rule"}</button>
    </div>
  </dialog>;
}
