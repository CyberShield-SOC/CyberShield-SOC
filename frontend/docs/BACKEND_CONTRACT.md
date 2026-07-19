# Connected backend contract

The frontend in `frontend/` is connected to the FastAPI service in `backend/`. Set `VITE_API_BASE_URL=/api` to activate it. The Vite development and preview servers proxy `/api` to `http://127.0.0.1:3000` so local browser sessions remain same-origin.

## Authentication

- `POST /api/auth/login` accepts `{ username, password, remember_me }`. `username` may contain the account username or email address.
- `GET /api/auth/me` restores a browser session on reload.
- `POST /api/auth/logout` revokes the server session and clears its cookies.
- The opaque session is stored in an HttpOnly, SameSite cookie. A separate non-secret CSRF cookie must match the `X-CSRF-Token` header for cookie-authenticated writes.
- FastAPI remains authoritative for Admin, Analyst, and Viewer permissions. The frontend route guard is only a user-experience layer.

The frontend never writes a password, bearer token, or session token to browser storage.

## Account administration

Every Users endpoint requires the Admin role:

| Action | Backend route | Security behavior |
| --- | --- | --- |
| List users and roles | `GET /api/users`, `GET /api/users/roles` | Never returns password hashes or session tokens. |
| Create account | `POST /api/users` | Hashes a 12–256 character temporary password with Argon2. |
| Edit identity and access | `PATCH /api/users/{id}` | Atomically updates name, username, email, role, and enabled state; duplicate identity values return `409`. |
| Reset password | `PATCH /api/users/{id}/password` | Hashes the replacement and revokes every existing session for the account. |
| Revoke sessions | `POST /api/users/{id}/sessions/revoke` | Signs the account out everywhere without changing its password. |
| Compatibility access updates | `PATCH /api/users/{id}/role`, `PATCH /api/users/{id}/active` | Retained for existing clients; disabling also revokes sessions. |

The API rejects demoting or disabling the final active Admin. The frontend also disables the current Admin's own role and enabled-state controls to avoid a confusing self-lockout, while identity and password controls remain available.

## Operational data

| Frontend feature | Backend route | Notes |
| --- | --- | --- |
| API health | `GET /api/health` | Polled by the sidebar and available as `/health` for direct service checks. |
| Event Logs | `GET /api/upload/latest` | Displays the latest persisted upload with stable database IDs and normalized fields. |
| File history | `GET /api/upload/history` | Returns server-side paginated upload metadata; the optional bounded `query` searches filenames and formats. |
| Historical event batch | `GET /api/upload/batches/{upload_id}` | Returns the logs and matched alerts for one validated upload UUID. |
| Log upload | `POST /api/upload` | Sends multipart field `logfile`; accepts `.log`, `.csv`, `.json`, and `.jsonl` up to the backend limit. |
| Alerts | `GET /api/alerts` | Maps backend severity/status enums to UI badges. |
| Alert status | `PATCH /api/alerts/{id}` | Server validates the role and accepted lifecycle enum. |
| Incidents | `GET /api/incidents` | Incidents remain linked to their required source alert. |
| Create incident | `POST /api/incidents` | Requires an existing unlinked alert ID. |
| Incident status | `PATCH /api/incidents/{id}` | Server records the authenticated updater. |
| All analyst notes | `GET /api/notes` | Returns a bounded, newest-first collection for the Notes workspace without per-incident requests. |
| Analyst notes | `GET/POST /api/incidents/{id}/notes` | Notes remain incident-scoped. |
| Edit note | `PATCH /api/notes/{id}` | Persists title, body, tags, pinned, and archived fields. |
| Delete note | `DELETE /api/notes/{id}` | Permanently removes one note; Admin and Analyst only. |

The dashboard is derived from the alert, incident, and latest-upload responses because this Sprint 1 backend does not expose an aggregate dashboard endpoint. `GET /api/upload/latest` includes each log's persisted `ingested_at` timestamp, allowing the dashboard to produce real interval buckets. KPI totals, security grade, unique/recurring IP counts, top sources, telemetry freshness, and analyst workload are transparent frontend aggregates over the selected period, not stored risk decisions. These cards render from the authoritative event, alert, and incident resources even if the optional aggregate request is delayed; detection coverage falls back to the distinct loaded rule IDs. The Threat analysis card prioritizes an active sudo/privilege-escalation detection and displays its server-provided reason, evidence count, user, source, rule, and window; otherwise it falls back to the highest-risk active alert or a clearly labeled correlation of repeated failed events. Terminal alerts are excluded. Telemetry freshness uses the newest valid ingestion timestamp; workload uses active severity, assignment, escalation, and investigation state.

An incident may contain at most five analyst notes. The repository locks the incident row before counting and creating a note so concurrent requests cannot pass the limit together. A sixth request returns `409`; deleting a note makes one slot available again.

## Features still local

The current backend has no API for workspace settings, AI inference/chat, reports, integrations, UTA SSO, MFA, end-user password recovery, or immutable note revisions. Admin-managed password reset is implemented, but the Forgot password page remains a support handoff. Supported interface preferences are stored only for the browser session; backend-managed security, retention, and masking policies are displayed as capability status rather than editable controls. Those screens do not claim that a server-side action occurred. After connected primary-credential login, the MFA screen remains in the route flow for UI continuity, but its six-digit check is frontend-only; the future backend must verify the challenge before issuing a fully authenticated session.

## Error handling

Requests include cookies, use a 12-second timeout, and do not expose backend stack traces. A protected-request `401` ends the frontend session, returns the user to login, and presents one concise expiry notice; the login endpoint is excluded to prevent redirect loops for invalid credentials. `403` is shown as a permission failure, and `409` is shown as a record conflict. Server-side validation remains authoritative.

The API adds `nosniff`, frame-denial, strict referrer, same-origin opener/resource, and restrictive permissions-policy headers. Authentication responses are marked `no-store`. Production deployments must use HTTPS, set `AUTH_COOKIE_SECURE=true`, keep an explicit CORS allow-list, and apply login rate limiting at the reverse proxy or identity-service boundary.

Connected status controls intentionally match the persisted enums: alerts support New, Reviewing, Escalated, and Closed; incidents support Open, Investigating, Resolved, and False Positive. Resolved and False Positive are terminal outcomes and retain `updated_by_user_id` plus the authoritative completion timestamp. The frontend does not silently translate unsupported mock-only states such as Acknowledged, Contained, Awaiting Approval, or the retired Closed incident state.

Upload requests accept `.log`, `.csv`, `.json`, and newline-delimited `.jsonl` data up to 10 MB. JSON accepts an object, an array, common event container keys, or one object per line and normalizes common nested SIEM fields. The browser performs an early check, while FastAPI independently enforces the extension, allowed MIME types, bounded reads, non-empty content, UTF-8 decoding, and binary/NUL rejection. A file with no parseable event records returns `422` and does not replace the latest successful dataset. After a successful upload, the interface switches to All available so historical event timestamps remain visible. Empty PATCH bodies and unknown query-filter enum values return validation errors before repository work begins.

Event Logs opens on the latest persisted upload. File history performs a bounded server-side search and lets the user inspect one historical batch without copying the full database into browser state. Selecting a batch temporarily pauses the global time filter so the complete upload is visible; **Pull latest data** refreshes the authoritative events, alerts, and dashboard resources and returns to the latest batch. History and batch reads require an authenticated Admin, Analyst, or Viewer, while upload writes remain limited to Admin and Analyst.
