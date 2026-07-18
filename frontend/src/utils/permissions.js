/** Canonical frontend role policy. FastAPI remains the authorization boundary. */
export const SOC_ROLES = Object.freeze({
  admin: "Admin",
  analyst: "Analyst",
  viewer: "Viewer",
});

function roleOf(user) {
  return typeof user?.role === "string" ? user.role : "";
}

export function canMutateInvestigations(user) {
  // A missing identity means deterministic sample mode, where every mutation
  // is tab-local. Connected identities must match an allow-listed role.
  return !user || [SOC_ROLES.admin, SOC_ROLES.analyst].includes(roleOf(user));
}

export function canAdministerWorkspace(user) {
  return !user || roleOf(user) === SOC_ROLES.admin;
}

export function canOpenUserManagement(user) {
  return canAdministerWorkspace(user);
}
