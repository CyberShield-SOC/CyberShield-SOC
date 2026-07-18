# Workflow validation and production boundary

This document is the regression checklist for CyberShield's implemented user journeys. Automated tests validate data rules and persisted API transitions; browser smoke tests validate the composed interface. It is intentionally explicit about capabilities that still need a backend contract.

## Supported workflow matrix

| Journey | Expected result | Persistence and authorization |
| --- | --- | --- |
| Login → MFA screen → dashboard | Valid credentials create a secure server session; the current frontend MFA screen completes the visual flow. | Login is server-validated. MFA is not yet server-enforced and must not be treated as a production security boundary. |
| Protected URL without a session | The route guard returns the browser to Login. A protected API `401` produces one concise expiration notice without looping. | FastAPI independently returns `401` for protected APIs. |
| Log upload → parse → event records → alerts | A valid `.log`, `.csv`, `.json`, or `.jsonl` file is bounded, parsed, persisted, and selected as the latest dataset. | Admin and Analyst only; backend revalidates type, size, content, and role. |
| Dashboard → recent alert → alert details | The exact selected alert remains pinned and its complete evidence model is displayed. | Viewer may read; mutation controls follow role permissions. |
| Alert → linked active incident | `Go to incident` selects the exact Open or Investigating record. | Shared in-memory selection; incident data remains server-authoritative. |
| Alert → linked terminal incident | `View incident` opens the exact Resolved or False Positive history detail once. Closing it clears the transient selection, so it does not reopen after route changes. | Terminal record and completion attribution are persisted. |
| Alert without incident → create incident | Eligible severity displays a create/promote action; the server prevents duplicate incident creation for one alert. | Admin and Analyst only; duplicate requests return `409`. |
| Event evidence → linked/create incident | Navigation selects the corresponding incident or the newly created record before changing routes. | Same incident authorization rules as Alerts. |
| Incident → status progression | Controls expose only Open, Investigating, Resolved, and False Positive. | FastAPI records the authenticated updater and completion time. |
| Incident → note | Create, edit, archive, pin, and delete are reflected in Notes and incident detail. A sixth active note is refused. | Admin and Analyst only; five-note limit is transactionally enforced. |
| Quick Resolve | Searchable alert selection composes alert review, evidence, incident status, notes, and AI context in one workspace. | Uses the same repository and permission checks; there is no parallel store. |
| AI analysis → copy/create | Output remains analyst-reviewed; copying targets the selected incident, then another active incident if none is selected. | Current inference is a frontend adapter. No autonomous response action occurs. |
| Notifications, filters, pagination, global search | State changes are bounded, keyboard accessible, and do not discard explicit record selection. A notification selects its exact alert or incident before navigation. | Browser-session UI state only. |
| Settings and secondary configuration | Implemented appearance/workspace preferences have visible effects. Unsupported server configuration is displayed read-only. | Browser-session preferences are not security policy. |
| Logout → return to login | The server session is revoked, cookies expire, and protected routes stop rendering. | Available to every authenticated role. |

## Role expectations

| Capability | Viewer | Analyst | Admin |
| --- | --- | --- | --- |
| Read dashboard, events, alerts, incidents, and notes | Yes | Yes | Yes |
| Upload logs or change alert/incident state | No | Yes | Yes |
| Create, edit, or delete analyst notes | No | Yes | Yes |
| Manage users and roles | No | No | Yes |
| Access Admin-only routes | No | No | Yes |

Disabled or hidden controls are usability safeguards. Every backend write checks the authenticated role again; frontend protection alone is never considered authorization.

## Automated regression commands

From `frontend/`:

```powershell
npm test
npm run build
```

From `backend/`:

```powershell
.venv\Scripts\python.exe -m pytest tests -q
```

The backend suite includes a persisted investigation flow: upload evidence, generate/review an alert, reject a duplicate incident, create an incident, add a note, transition to Investigating and Resolved, then reload the incident and global notes collection. Each test is isolated inside a rollback-only database transaction so validation never changes the development dataset.

See `INTERACTION_TEST_REPORT.md` for the latest route-by-route browser audit, exact test totals, discovered fixes, and release-environment boundaries.

## Production work that remains

- Add a server-issued and server-verified MFA challenge before treating the MFA page as enforcement.
- Connect the AI adapter to an approved inference service with retention, redaction, audit, timeout, and human-approval controls.
- Add persistence and authorization contracts before making secondary configuration editable.
- Apply public login throttling, account lockout policy, TLS, secure cookies, secret rotation, monitoring, backups, and recovery procedures in the deployment environment.
- Run dependency, accessibility, browser/device, load, and penetration testing in the release pipeline. Passing the local suites is not a substitute for those controls.

## Extension rules

- Add domain behavior to a shared utility or repository contract instead of duplicating status arrays or raw API calls inside pages.
- Keep server values normalized at the repository boundary and keep backend errors free of internal details.
- Comment security boundaries and non-obvious concurrency behavior; prefer descriptive names over comments that restate JSX.
- Add a deterministic test for every parser, lifecycle, permission, export, or persistence rule before changing its interface.
