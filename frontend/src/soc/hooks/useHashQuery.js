import { useEffect } from "react";

/** The `?q=` the global search put on the hash route, capped like the input. */
export function readHashQuery() {
  const queryString = window.location.hash.split("?", 2)[1] || "";
  return (new URLSearchParams(queryString).get("q") || "").slice(0, 200);
}

/** Calls `onChange` with the new `?q=` whenever the hash route changes. */
export function useHashQuery(onChange) {
  useEffect(() => {
    function syncGlobalSearch() {
      onChange(readHashQuery());
    }

    window.addEventListener("hashchange", syncGlobalSearch);
    return () => window.removeEventListener("hashchange", syncGlobalSearch);
  }, [onChange]);
}
