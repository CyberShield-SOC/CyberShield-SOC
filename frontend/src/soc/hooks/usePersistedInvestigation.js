import { useEffect, useState } from "react";
import { socRepository } from "../services/socRepository.js";

export function usePersistedInvestigation(kind, record, mode, revision) {
  const [state, setState] = useState({ id: null, data: null, loading: false, error: "" });
  const id = record?.id;
  const version = record?.version;
  useEffect(() => {
    if (mode !== "api" || !id) return;
    let active = true;
    setState({ id, data: null, loading: true, error: "" });
    const load = kind === "alert" ? "getAlertInvestigation" : "getIncidentInvestigation";
    socRepository[load](id).then((data) => {
      if (active) setState({ id, data, loading: false, error: "" });
    }).catch((error) => {
      if (active) setState({ id, data: null, loading: false, error: error.message });
    });
    return () => { active = false; };
  }, [id, kind, mode, revision, version]);
  return state.id === id ? state : { data: null, loading: false, error: "" };
}
