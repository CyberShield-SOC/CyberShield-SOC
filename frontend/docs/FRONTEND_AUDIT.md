# Frontend audit — July 18, 2026

## Verified

- Production build succeeds with route-level code splitting; the entry bundle is 71.88 kB gzip and CSS is 29.28 kB gzip.
- All 86 unit and contract tests pass, including large-import, chart, auth, RBAC, upload, export, workflow, and persistence edge cases.
- `npm audit --omit=dev --offline` reports zero production dependency vulnerabilities.
- API transport uses HttpOnly cookies, CSRF headers, bounded timeouts, generic errors, and centralized 401 handling. Routes and role-aware actions are guarded in the UI while FastAPI remains authoritative.
- No dynamic HTML injection, `eval`, credential logging, or browser-stored bearer tokens were found.

## Improvements applied

- Coalesced identical in-flight API reads during synchronized workspace refreshes without caching completed responses.
- Paused health polling in hidden tabs and refreshes it when analysts return.
- Removed the 1.5 MB login-art preload from compact layouts where the artwork is hidden.
- Replaced spread-based timestamp extrema that could fail on very large SIEM imports; added 150,000-record regression cases.

## Deployment gates outside this frontend

- Configure HTTPS/HSTS, CSP, frame protection, request/response size limits, observability, backups, and rate limits on the production host/API.
- Complete and integration-test real UTA SSO, MFA, recovery, settings persistence, and AI service contracts before presenting those flows as enforced security controls.
- Run connected end-to-end tests for all three roles against an isolated production-like database, including expired/revoked sessions and direct forbidden API calls.
- Add CI checks for build, tests, dependency scanning, browser accessibility, and cross-browser workflows. Re-run after every dependency or backend-contract change.
