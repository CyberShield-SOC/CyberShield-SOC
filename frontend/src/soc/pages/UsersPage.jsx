import { useCallback, useEffect, useMemo, useState } from "react";
import { KeyRound, LogOut, Plus, RefreshCw, Save, Search, ShieldCheck, UserRoundCog, X } from "lucide-react";
import { InlineNotice, PageHeader, Panel, StatCard, StatusBadge } from "../components/Ui";
import { useSocWorkspace } from "../context/SocWorkspaceContext";
import { socRepository } from "../services/socRepository";
import {
  normalizeNewWorkspaceUser,
  normalizeWorkspaceUserUpdate,
  validateNewWorkspaceUser,
  validateWorkspacePassword,
  validateWorkspaceUserUpdate,
} from "../utils/userValidation";

const EMPTY_NEW_USER = Object.freeze({
  username: "",
  email: "",
  fullName: "",
  password: "",
  confirmPassword: "",
  role: "Analyst",
});

const EMPTY_PASSWORD = Object.freeze({ password: "", confirmPassword: "" });

function notifySessionInvalidated() {
  const detail = Object.freeze({ path: "/users", reason: "credentials_changed" });
  window.dispatchEvent(new window.CustomEvent("cybershield:unauthorized", { detail }));
}

export default function UsersPage() {
  const { canAdminister, currentUser, repositoryMode } = useSocWorkspace();
  const [users, setUsers] = useState([]);
  const [roles, setRoles] = useState([]);
  const [selectedId, setSelectedId] = useState(null);
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [createOpen, setCreateOpen] = useState(false);
  const [newUser, setNewUser] = useState(EMPTY_NEW_USER);
  const [newUserErrors, setNewUserErrors] = useState({});
  const [draftErrors, setDraftErrors] = useState({});
  const [passwordOpen, setPasswordOpen] = useState(false);
  const [passwordDraft, setPasswordDraft] = useState(EMPTY_PASSWORD);
  const [passwordErrors, setPasswordErrors] = useState({});
  const [revokeTarget, setRevokeTarget] = useState(null);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [draft, setDraft] = useState({
    username: "",
    email: "",
    fullName: "",
    role: "Viewer",
    isActive: true,
  });

  const loadUsers = useCallback(async () => {
    setLoading(true);
    setError("");
    setMessage("");
    try {
      const [nextUsers, nextRoles] = await Promise.all([
        socRepository.getUsers(),
        socRepository.getUserRoles(),
      ]);
      setUsers(nextUsers);
      setRoles(nextRoles);
      setSelectedId((current) => nextUsers.some((user) => user.id === current) ? current : nextUsers[0]?.id || null);
    } catch (loadError) {
      setError(loadError.message || "Workspace users could not be loaded.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadUsers();
  }, [loadUsers]);

  const selected = users.find((user) => user.id === selectedId) || null;
  useEffect(() => {
    if (selected) {
      setDraft({
        username: selected.username,
        email: selected.email,
        fullName: selected.fullName,
        role: selected.role,
        isActive: selected.isActive,
      });
      setDraftErrors({});
    }
  }, [selected]);

  const filtered = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase();
    if (!normalizedQuery) return users;
    return users.filter((user) => (
      `${user.fullName} ${user.username} ${user.email} ${user.role}`.toLowerCase().includes(normalizedQuery)
    ));
  }, [query, users]);

  const activeCount = users.filter((user) => user.isActive).length;
  const adminCount = users.filter((user) => user.role === "Admin" && user.isActive).length;
  const analystCount = users.filter((user) => user.role === "Analyst" && user.isActive).length;
  const viewerCount = users.filter((user) => user.role === "Viewer" && user.isActive).length;
  const isCurrentUser = Boolean(selected && Number(selected.id) === Number(currentUser?.id));
  const hasChanges = Boolean(selected) && (
    draft.username !== selected.username
    || draft.email !== selected.email
    || draft.fullName !== selected.fullName
    || draft.role !== selected.role
    || draft.isActive !== selected.isActive
  );
  const selectedRole = roles.find((role) => role.name === draft.role);

  async function saveUser(event) {
    event.preventDefault();
    if (!selected || !canAdminister || !hasChanges || saving) return;
    const normalized = normalizeWorkspaceUserUpdate(draft);
    const validationErrors = validateWorkspaceUserUpdate(normalized);
    setDraftErrors(validationErrors);
    if (Object.keys(validationErrors).length) return;

    setSaving(true);
    setError("");
    setMessage("");
    try {
      const updated = await socRepository.updateUser(selected.id, {
        ...normalized,
        // The active account cannot demote or disable itself through this UI.
        role: isCurrentUser ? selected.role : normalized.role,
        isActive: isCurrentUser ? selected.isActive : normalized.isActive,
      });
      setUsers((current) => current.map((user) => user.id === updated.id ? updated : user));
      setMessage(`${updated.fullName || updated.username} was updated.`);
    } catch (saveError) {
      const saveMessage = saveError.message || "The user could not be updated.";
      await loadUsers();
      setError(saveMessage);
    } finally {
      setSaving(false);
    }
  }

  function openPasswordReset() {
    if (!selected) return;
    setPasswordDraft(EMPTY_PASSWORD);
    setPasswordErrors({});
    setError("");
    setPasswordOpen(true);
  }

  async function resetPassword(event) {
    event.preventDefault();
    if (!selected || !canAdminister || saving) return;
    const validationErrors = validateWorkspacePassword(passwordDraft);
    setPasswordErrors(validationErrors);
    if (Object.keys(validationErrors).length) return;

    setSaving(true);
    setError("");
    setMessage("");
    try {
      const result = await socRepository.resetUserPassword(selected.id, passwordDraft.password);
      setPasswordDraft(EMPTY_PASSWORD);
      setPasswordOpen(false);
      if (isCurrentUser && repositoryMode === "api") {
        notifySessionInvalidated();
        return;
      }
      setMessage(`Password reset for ${selected.fullName || selected.username}. ${result.sessionsRevoked} active session${result.sessionsRevoked === 1 ? "" : "s"} revoked.`);
    } catch (resetError) {
      setError(resetError.message || "The password could not be reset.");
    } finally {
      setSaving(false);
    }
  }

  async function revokeSessions() {
    if (!revokeTarget || !canAdminister || saving) return;
    const target = revokeTarget;
    setSaving(true);
    setError("");
    setMessage("");
    try {
      const result = await socRepository.revokeUserSessions(target.id);
      setRevokeTarget(null);
      if (Number(target.id) === Number(currentUser?.id) && repositoryMode === "api") {
        notifySessionInvalidated();
        return;
      }
      setMessage(`${result.sessionsRevoked} active session${result.sessionsRevoked === 1 ? "" : "s"} revoked for ${target.fullName || target.username}.`);
    } catch (revokeError) {
      setError(revokeError.message || "Active sessions could not be revoked.");
    } finally {
      setSaving(false);
    }
  }

  function openCreateUser() {
    setNewUser(EMPTY_NEW_USER);
    setNewUserErrors({});
    setError("");
    setCreateOpen(true);
  }

  async function createUser(event) {
    event.preventDefault();
    if (!canAdminister || saving) return;
    const errors = validateNewWorkspaceUser(newUser);
    setNewUserErrors(errors);
    if (Object.keys(errors).length) return;

    setSaving(true);
    setError("");
    setMessage("");
    try {
      const created = await socRepository.createUser(normalizeNewWorkspaceUser(newUser));
      setUsers((current) => [...current, created].sort((left, right) => left.id - right.id));
      setSelectedId(created.id);
      setCreateOpen(false);
      setNewUser(EMPTY_NEW_USER);
      setMessage(`${created.fullName || created.username} was created as ${created.role}.`);
    } catch (createError) {
      setError(createError.message || "The user could not be created.");
    } finally {
      setSaving(false);
    }
  }

  return (
    <>
      <PageHeader
        title="Users"
        description="Manage workspace roles and account access. Backend authorization remains the enforcement boundary."
        actions={<><button className="soc-button secondary" type="button" disabled={loading || saving} onClick={loadUsers}><RefreshCw size={15} />Refresh users</button><button className="soc-button primary" type="button" disabled={!canAdminister || loading || saving} onClick={openCreateUser}><Plus size={15} />Create user</button></>}
      />

      <div className="soc-stats-grid">
        <StatCard label="Active users" value={activeCount} trend={`${users.length - activeCount} disabled`} tone="success" />
        <StatCard label="Administrators" value={adminCount} trend="Workspace control" />
        <StatCard label="Analysts" value={analystCount} trend="Investigation access" />
        <StatCard label="Viewers" value={viewerCount} trend="Read-only access" />
      </div>

      {error && <InlineNotice tone="error" title="User management error">{error}</InlineNotice>}
      {message && <InlineNotice tone="success" title="Changes saved">{message}</InlineNotice>}

      <div className="user-management-workspace">
        <Panel title="Workspace directory" subtitle={loading ? "Loading users…" : `${filtered.length} of ${users.length} users`}>
          <label className="secondary-search"><Search size={16} /><span className="sr-only">Search workspace users</span><input type="search" maxLength="200" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search names, emails, or roles…" /></label>
          <div className="user-directory-list" aria-busy={loading}>
            {filtered.map((user) => (
              <button key={user.id} type="button" className={selected?.id === user.id ? "selected" : ""} onClick={() => setSelectedId(user.id)}>
                <span className="user-directory-avatar">{(user.fullName || user.username).split(/\s+/).slice(0, 2).map((part) => part[0]).join("").toUpperCase()}</span>
                <span><strong>{user.fullName || user.username}</strong><small>{user.email} · {user.role}</small></span>
                <StatusBadge status={user.isActive ? "enabled" : "disabled"} />
              </button>
            ))}
            {!loading && !filtered.length && <div className="table-empty"><Search size={22} /><strong>No users match</strong><span>Adjust the search to restore the workspace directory.</span></div>}
          </div>
        </Panel>

        <Panel title="Edit workspace access" subtitle={selected ? selected.email : "Select a user"}>
          {selected ? (
            <form className="workspace-user-editor" onSubmit={saveUser}>
              <div className="workspace-user-heading"><span><UserRoundCog size={21} /></span><div><h3>{selected.fullName || selected.username}</h3><p>@{selected.username}</p></div></div>
              <dl>
                <div><dt>User ID</dt><dd className="mono">{selected.id}</dd></div>
                <div><dt>Current access</dt><dd><StatusBadge status={selected.isActive ? "enabled" : "disabled"} /></dd></div>
              </dl>
              <div className="workspace-user-fields">
                <label>Full name<input value={draft.fullName} maxLength="100" autoComplete="off" disabled={!canAdminister || saving} aria-invalid={Boolean(draftErrors.fullName)} onChange={(event) => setDraft((current) => ({ ...current, fullName: event.target.value }))} /><span className="soc-field-error">{draftErrors.fullName}</span></label>
                <label>Username<input value={draft.username} maxLength="50" autoComplete="off" disabled={!canAdminister || saving} required aria-invalid={Boolean(draftErrors.username)} onChange={(event) => setDraft((current) => ({ ...current, username: event.target.value }))} /><span className="soc-field-error">{draftErrors.username}</span></label>
                <label className="span-2">Email<input type="email" value={draft.email} maxLength="254" autoComplete="off" disabled={!canAdminister || saving} required aria-invalid={Boolean(draftErrors.email)} onChange={(event) => setDraft((current) => ({ ...current, email: event.target.value }))} /><span className="soc-field-error">{draftErrors.email}</span></label>
              </div>
              <label>Workspace role<select value={draft.role} disabled={!canAdminister || saving || isCurrentUser} aria-describedby={isCurrentUser ? "current-admin-access-note" : undefined} onChange={(event) => setDraft((current) => ({ ...current, role: event.target.value }))}>{roles.map((role) => <option key={role.id} value={role.name}>{role.name}</option>)}</select></label>
              <p className="workspace-role-description"><ShieldCheck size={14} />{selectedRole?.description || "Role permissions are enforced by the connected service."}</p>
              <label className="workspace-user-active"><input type="checkbox" checked={draft.isActive} disabled={!canAdminister || saving || isCurrentUser} aria-describedby={isCurrentUser ? "current-admin-access-note" : undefined} onChange={(event) => setDraft((current) => ({ ...current, isActive: event.target.checked }))} /><span><strong>Account enabled</strong><small>Disabling an account immediately revokes its active sessions.</small></span></label>
              {isCurrentUser && <InlineNotice id="current-admin-access-note" tone="info" title="Current administrator">Edit your identity here, but use another Admin account to change your own role or enabled state. This prevents an accidental lockout.</InlineNotice>}
              <div className="workspace-security-actions" aria-label="Account security actions">
                <button className="soc-button secondary" type="button" disabled={!canAdminister || saving} onClick={openPasswordReset}><KeyRound size={15} />Reset password</button>
                <button className="soc-button danger" type="button" disabled={!canAdminister || saving} onClick={() => setRevokeTarget(selected)}><LogOut size={15} />Revoke sessions</button>
              </div>
              <InlineNotice tone="info" title={repositoryMode === "api" ? "Protected account controls" : "Sample workspace controls"}>{repositoryMode === "api" ? "Identity, access, password, and session changes use CSRF-protected Admin-only endpoints. Passwords are hashed by the backend and never returned." : "Identity changes persist only for this browser session. Sample mode never stores the password you enter."}</InlineNotice>
              <button className="soc-button primary full" type="submit" disabled={!canAdminister || !hasChanges || saving}>{saving ? <span className="soc-spinner small" /> : <Save size={15} />}{saving ? "Saving…" : "Save access changes"}</button>
            </form>
          ) : <div className="detail-placeholder"><UserRoundCog size={24} /><strong>Select a workspace user</strong><span>Review identity, role, and account access.</span></div>}
        </Panel>
      </div>

      {createOpen && (
        <div className="soc-modal-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget && !saving) setCreateOpen(false); }}>
          <section className="soc-modal create-user-modal" role="dialog" aria-modal="true" aria-labelledby="create-user-title">
            <header>
              <div><h2 id="create-user-title">Create workspace user</h2><p>Create an Admin, Analyst, or Viewer account. Passwords are sent only to the protected account-creation endpoint.</p></div>
              <button type="button" disabled={saving} onClick={() => setCreateOpen(false)} aria-label="Close"><X size={18} /></button>
            </header>
            <form onSubmit={createUser} noValidate>
              <label>Full name <input value={newUser.fullName} maxLength="100" autoComplete="name" aria-invalid={Boolean(newUserErrors.fullName)} onChange={(event) => setNewUser((current) => ({ ...current, fullName: event.target.value }))} /><span className="soc-field-error">{newUserErrors.fullName}</span></label>
              <label>Username <input value={newUser.username} maxLength="50" autoComplete="username" required aria-invalid={Boolean(newUserErrors.username)} onChange={(event) => setNewUser((current) => ({ ...current, username: event.target.value }))} /><span className="soc-field-error">{newUserErrors.username}</span></label>
              <label>Email <input type="email" value={newUser.email} maxLength="254" autoComplete="email" required aria-invalid={Boolean(newUserErrors.email)} onChange={(event) => setNewUser((current) => ({ ...current, email: event.target.value }))} /><span className="soc-field-error">{newUserErrors.email}</span></label>
              <label>Workspace role <select value={newUser.role} aria-invalid={Boolean(newUserErrors.role)} onChange={(event) => setNewUser((current) => ({ ...current, role: event.target.value }))}>{roles.map((role) => <option key={role.id} value={role.name}>{role.name}</option>)}</select><span className="soc-field-error">{newUserErrors.role}</span></label>
              <label>Temporary password <input type="password" value={newUser.password} minLength="12" maxLength="256" autoComplete="new-password" required aria-invalid={Boolean(newUserErrors.password)} onChange={(event) => setNewUser((current) => ({ ...current, password: event.target.value }))} /><span className="soc-field-error">{newUserErrors.password}</span></label>
              <label>Confirm password <input type="password" value={newUser.confirmPassword} minLength="12" maxLength="256" autoComplete="new-password" required aria-invalid={Boolean(newUserErrors.confirmPassword)} onChange={(event) => setNewUser((current) => ({ ...current, confirmPassword: event.target.value }))} /><span className="soc-field-error">{newUserErrors.confirmPassword}</span></label>
              <div className="soc-modal-actions"><button className="soc-button secondary" type="button" disabled={saving} onClick={() => setCreateOpen(false)}>Cancel</button><button className="soc-button primary" type="submit" disabled={saving}>{saving ? <span className="soc-spinner small" /> : <Plus size={15} />}{saving ? "Creating…" : "Create user"}</button></div>
            </form>
          </section>
        </div>
      )}

      {passwordOpen && selected && (
        <div className="soc-modal-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget && !saving) setPasswordOpen(false); }}>
          <section className="soc-modal password-reset-modal" role="dialog" aria-modal="true" aria-labelledby="password-reset-title">
            <header>
              <div><h2 id="password-reset-title">Reset password</h2><p>Set a temporary password for {selected.fullName || selected.username}. Every existing session for this account will be revoked.</p></div>
              <button type="button" disabled={saving} onClick={() => setPasswordOpen(false)} aria-label="Close"><X size={18} /></button>
            </header>
            {isCurrentUser && <InlineNotice tone="warning" title="You are resetting your own password">After the reset, this session will close and you must sign in with the new password.</InlineNotice>}
            <form onSubmit={resetPassword} noValidate>
              <label>New temporary password<input type="password" value={passwordDraft.password} minLength="12" maxLength="256" autoComplete="new-password" required aria-invalid={Boolean(passwordErrors.password)} onChange={(event) => setPasswordDraft((current) => ({ ...current, password: event.target.value }))} /><span className="soc-field-error">{passwordErrors.password}</span></label>
              <label>Confirm password<input type="password" value={passwordDraft.confirmPassword} minLength="12" maxLength="256" autoComplete="new-password" required aria-invalid={Boolean(passwordErrors.confirmPassword)} onChange={(event) => setPasswordDraft((current) => ({ ...current, confirmPassword: event.target.value }))} /><span className="soc-field-error">{passwordErrors.confirmPassword}</span></label>
              <div className="soc-modal-actions"><button className="soc-button secondary" type="button" disabled={saving} onClick={() => setPasswordOpen(false)}>Cancel</button><button className="soc-button primary" type="submit" disabled={saving}>{saving ? <span className="soc-spinner small" /> : <KeyRound size={15} />}{saving ? "Resettingâ€¦" : "Reset password"}</button></div>
            </form>
          </section>
        </div>
      )}

      {revokeTarget && (
        <div className="soc-modal-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget && !saving) setRevokeTarget(null); }}>
          <section className="soc-modal confirmation-modal" role="alertdialog" aria-modal="true" aria-labelledby="revoke-sessions-title" aria-describedby="revoke-sessions-description">
            <header>
              <div><h2 id="revoke-sessions-title">Revoke active sessions?</h2><p id="revoke-sessions-description">{revokeTarget.fullName || revokeTarget.username} will be signed out on every device. Their account and password will remain unchanged.</p></div>
              <button type="button" disabled={saving} onClick={() => setRevokeTarget(null)} aria-label="Close"><X size={18} /></button>
            </header>
            {Number(revokeTarget.id) === Number(currentUser?.id) && <InlineNotice tone="warning" title="This includes your current session">You will return to the sign-in page after the sessions are revoked.</InlineNotice>}
            <div className="soc-modal-actions"><button className="soc-button secondary" type="button" disabled={saving} onClick={() => setRevokeTarget(null)}>Cancel</button><button className="soc-button danger" type="button" disabled={saving} onClick={revokeSessions}><LogOut size={15} />{saving ? "Revokingâ€¦" : "Revoke sessions"}</button></div>
          </section>
        </div>
      )}

    </>
  );
}
