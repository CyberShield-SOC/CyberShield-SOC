import { useCallback, useEffect, useState } from "react";
import { socRepository } from "../services/socRepository.js";

export function usePersistedInvestigation(kind, record, mode, revision) {
  const [state, setState] = useState({ id: null, data: null, loading: false, error: "" });
  const id = record?.id;
  const version = record?.version;
  const identity = `${kind}:${id}:${version ?? ""}`;
  const [reloadVersion, setReloadVersion] = useState(0);
  const reload = useCallback(() => setReloadVersion((current) => current + 1), []);
  useEffect(() => {
    if (mode !== "api" || !id) return;
    let active = true;
    setState({ id, identity, data: null, loading: true, error: "" });
    const load = kind === "alert" ? "getAlertInvestigation" : "getIncidentInvestigation";
    socRepository[load](id).then((data) => {
      if (active) setState({ id, identity, data, loading: false, error: "" });
    }).catch((error) => {
      if (active) setState({ id, identity, data: null, loading: false, error: error.message || "Investigation details could not be loaded." });
    });
    return () => { active = false; };
  }, [id, identity, kind, mode, revision, version, reloadVersion]);
  return { ...(state.identity === identity && mode === "api" ? state : { data: null, loading: mode === "api" && Boolean(id), error: "" }), reload };
}
