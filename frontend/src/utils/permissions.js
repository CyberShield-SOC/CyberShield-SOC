/** Canonical frontend role policy. FastAPI remains the authorization boundary. */
export const SOC_ROLES = Object.freeze({
  admin: "Admin",
  analyst: "Analyst",
  viewer: "Viewer",
});

function roleOf(user) {
  return user?.is_active === false || user?.isActive === false ? "" : typeof user?.role === "string" ? user.role : "";
}

export function canReadWorkspace(user) {
  return !user || Object.values(SOC_ROLES).includes(roleOf(user));
}

export function canManageRules(user) {
  return canMutateInvestigations(user);
}

export function canExportReports(user) {
  return canReadWorkspace(user);
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
