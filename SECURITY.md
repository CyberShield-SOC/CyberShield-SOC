# Security notes

## Current boundary

The application uses the FastAPI/PostgreSQL service in `backend/`. FastAPI validates credentials, revocable sessions, Admin/Analyst/Viewer roles, event upload, alerts, incidents, and incident notes. Client-side validation still improves usability only; it is not an authorization control. Password recovery, UTA SSO, MFA, perimeter blocks, settings, and AI conclusions still require backend or identity-provider contracts.

No password or MFA code is logged or persisted by the frontend. Connected authentication uses an opaque HttpOnly, SameSite cookie and double-submit CSRF protection; the browser adapter deliberately discards the legacy bearer-token response. Local storage contains only the non-sensitive theme preference. Session storage is limited to mock-mode state, notification preferences, and settings drafts. Connected incident notes and evidence are read from the authorized backend.

Protected frontend routes reduce accidental navigation but do not provide authorization. Attackers can modify browser state and JavaScript. The server must validate the authenticated session, tenant, role, record-level authorization, and workflow transition for every request. User identity, role, enabled-state, password-reset, and session-revocation controls are visible only to frontend Admin identities, call CSRF-protected endpoints, and remain independently restricted by FastAPI's Admin role dependency. Password resets use Argon2 and revoke existing sessions; disabling an account also revokes sessions. The backend rejects any change that would remove the final active administrator, while the UI additionally prevents the active Admin from demoting or disabling itself.

The event exporter neutralizes common spreadsheet-formula prefixes before producing CSV. Local log inspection is limited to supported text extensions and 5 MB; production ingestion must still validate content, decompress archives safely, enforce quotas, quarantine malformed data, and parse files on the server.

## Production deployment checklist

- Serve the site and every API endpoint over HTTPS with HSTS.
- Configure a strict Content Security Policy at the hosting layer. Start with `default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'`, then add only the exact identity-provider and API origins required by the deployment.
- Keep `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, and a restrictive `Permissions-Policy`.
- Use frame protection through CSP `frame-ancestors`; do not rely only on a meta tag.
- Keep secrets out of `VITE_*` variables because Vite exposes them to browser code.
- Use secure, `HttpOnly`, `SameSite` session cookies; do not store bearer tokens in local storage.
- Enforce CSRF protection on state-changing endpoints and verify `Origin`/`Referer` where appropriate.
- Authorize every event, incident, report, user, integration, and settings request on the server. Hiding a route or button is not access control.
- Rate-limit authentication, event upload, search, export, and AI-analysis endpoints. Cap query complexity and response size.
- Keep logout idempotent and clear browser cookies even when the server session is already expired or revoked.
- Bound credential, text, filter, and file inputs at both the browser and API layers. Uploaded log content is read only one byte past the configured limit and binary/NUL data is rejected before parsing.
- Validate AI-analysis inputs, isolate retrieved evidence by tenant, log model/tool actions, and require human approval for containment or destructive operations.
- Redact sensitive event fields in logs and telemetry. Never record passwords, MFA codes, session cookies, recovery tokens, or raw authorization headers.
- Pin and review dependencies, run `npm audit`, and rebuild from a locked dependency file in CI.
- Add automated integration tests against the real login, SSO, MFA, logout, timeout, and account-recovery flows.

Security headers must be configured on the production host or reverse proxy; Vite configuration alone does not control a deployed CDN or web server.

## Latest frontend verification

The July 18, 2026 audit passed the production build, 86 focused unit/contract tests, and an offline production-dependency audit with zero reported vulnerabilities. This is a point-in-time frontend result, not a substitute for CI scanning, backend authorization tests, penetration testing, or an external deployment review.
