# Full interaction test report

Audit date: July 17, 2026

This report records the deterministic checks performed against the current CyberShield frontend and connected FastAPI backend. It separates live browser coverage from automated contract coverage so a passing local test is not mistaken for an unimplemented production integration.

## Result

- Frontend unit and contract tests: **82 passed**
- Backend API and persistence tests: **140 passed**
- Production frontend build: **passed**
- Production dependency audit: **0 known vulnerabilities**
- Python compilation check: **passed**
- Static unsafe-sink scan: **no `dangerouslySetInnerHTML`, dynamic evaluation, browser-stored tokens, debug logging, or unfinished markers found**

The backend tests run inside rollback-only database transactions. Test-created users, alerts, incidents, notes, and uploads cannot pollute the development database.

## Live browser coverage

### Authentication and route protection

- Required, malformed-email, and incorrect-credential feedback
- Password show/hide, Remember Me control, and authentication theme transition
- Forgot-password privacy-preserving response, UTA SSO handoff page, and support guidance
- Direct uninitiated MFA rejection, incomplete-code validation, resend explanation, and six-digit completion
- Intended protected route restoration after authentication
- Unknown-route recovery
- Sign out, logout-success confirmation, return to Login, and protected-route rejection after logout
- Thirty-minute sample session expiry was observed returning the audit tab to Login
- Protected-request `401` handling is covered by a frontend contract test: Login responses do not trigger a redirect loop, while a protected request clears the session and presents one concise expiry notice

### Dashboard and application shell

- Every dashboard action target, recent-alert mouse and keyboard selection, and global time-range filtering
- Global search and keyboard shortcut behavior
- API-health and workspace refresh controls
- Events-ingested line chart: 12 plotted points
- Severity stacked chart: 12 interval columns
- Alert-status donut chart and accessible chart labels
- Security grade, unique/recurring IP, telemetry readiness, and analyst workload cards
- Help-center and profile menus, including the absence of the removed Workspace Settings menu action

### Events, alerts, incidents, and Quick Resolve

- Event search, all facets, empty state, clear, keyboard row selection, pagination, direct-page clamping, CSV export control, AI navigation, and linked-incident navigation
- Selected events and alerts remain pinned across page changes and route round trips
- Alert search, all facets, status changes, evidence, rule detail, recommendations, note modal validation/cancel/save, linked-incident navigation, and incident promotion
- Incident search, priority/status filters, create validation/cancel/save, Open to Investigating to Resolved and False Positive transitions, completion time and actor, terminal-history removal, history search/export/close, and no modal resurrection after route changes
- Incident tracking picker, playbook controls, five-note limit, scrollable notes, and terminal completion
- Quick Resolve searchable alert picker, exact alert round trip, incident creation, four-step checklist, note, AI context, status transition, resolution, and exact history view

### Notes, AI, notifications, settings, and support pages

- Analyst-note search and facets, create validation, pin, edit/cancel/save, version history, archive/restore, delete confirmation, storage summary, and exact event/alert/incident links
- Missing/stale note links render an unavailable state instead of navigating to a blank detail panel
- AI question/answer, follow-up, all suggested prompts, evidence display, all recommendation routes, clear chat, disabled-AI state, note creation, and draft-incident creation
- Notification exact-record navigation, per-item read/unread, all read/unread, All/Unread views, individual clear, clear all, empty state, and Escape dismissal
- Workspace validation, save/discard, theme, density, text size, reduced motion, contrast, notification preferences, AI availability, read-only security/data boundaries, and documentation-to-Help routing
- Help search/empty state, all six guide destinations, shortcuts, connection disclosure, and role descriptions
- Threat Detection, Reports, Manage, Users, and Integrations search, selection, empty state, and honest read-only configuration notice

## Automated backend coverage

The API suite covers cookie and bearer authentication, Remember Me lifetime, generic invalid/inactive-account responses, Viewer/Analyst/Admin read and write matrices, protected API rejection, user administration, upload type/size/content checks, log parsing and alert generation, duplicate-incident prevention, note create/edit/pin/archive/delete, five-note enforcement, every incident status, completion attribution, and persisted reloads.

The complete persisted chain is exercised as:

`Login -> upload log -> parse -> generate alert -> dashboard data -> alert detail -> create incident -> add note -> update status -> reload -> confirm saved state`

## Defects found and fixed during this audit

1. Notification clicks navigated to Alerts or Incidents without selecting the notified record. Notifications now carry a bounded record identifier and set the shared selection before navigation.
2. Event selection lived only inside the Event Logs page. It now uses shared workspace selection and survives pagination and route changes.
3. Analyst-note links could navigate to records removed from the active sample dataset after a hot reload. Missing targets now render `Unavailable`.
4. The local inspector used a stale 5 MB limit and accepted `.txt` while the UI/backend contract specified 10 MB and `.log`, `.csv`, `.json`, or `.jsonl`. Both modes now agree, with content-level tests.
5. Backend API tests previously committed into the development database. Every test now runs in a rollback-only transaction.

## Boundaries that still require release-environment testing

- The in-app browser test binding cannot programmatically choose a native file in the file picker. File contents, limits, formats, backend parsing, persistence, and generated records are covered by automated tests, but the OS picker itself still needs a manual release smoke test.
- The live sample browser session is an Admin session. Viewer/Analyst behavior is covered by the frontend permission-policy tests and the 51-case backend role matrix; role-specific visual screenshots remain a release QA task.
- The browser binding used for this audit does not resize its viewport. Responsive CSS and narrow-screen structures remain in the build, but physical mobile devices, browser zoom, and screen readers must be exercised in release QA.
- UTA SSO, password delivery, server-verified MFA, external AI inference, notification delivery, and writable secondary configuration still require their documented backend/service contracts.
- Load, failover, backup/restore, penetration, and cross-browser testing belong in the deployment pipeline and are not proven by this local audit.

## Repeat the checks

From `frontend/`:

```powershell
npm test
npm run build
npm audit --omit=dev --offline
```

From `backend/`:

```powershell
.venv\Scripts\python.exe -m pytest tests -q -p no:cacheprovider
.venv\Scripts\python.exe -m compileall -q app tests
```
