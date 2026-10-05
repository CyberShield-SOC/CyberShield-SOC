# Sprint 6 backend additions

## PT-01: Correlation and evidence data model

- Added correlation groups with entity details, observation times, severity, confidence, grouping reasons, and captured rule configuration.
- Added relationships linking groups to original log events, alerts, and upload batches, plus direct alert-to-event evidence links.
- Added foreign keys, indexes, uniqueness constraints, and an Alembic migration that preserves original source records.
- Added schema and migration coverage for source preservation, duplicate links, upgrade, and rollback.

## PT-02: Correlation engine

- Added correlation of normalized events and alerts by permitted source IP, username, hostname, upload batch, and rule context.
- Added configurable time windows with inclusive boundaries and deterministic grouping.
- Added duplicate-reference handling and separation of unrelated activity.
- Added structured results containing exact evidence identities, captured rule context, and readable grouping explanations.
- Added tests for matching and nonmatching entities, window boundaries, duplicates, and unrelated events.

## PT-03: Persistence and evidence APIs

- Added PostgreSQL persistence for correlation groups and their evidence relationships.
- Added authenticated endpoints for group lists/details, linked alerts, source events, upload batches, and rule context.
- Added evidence pagination, completeness reporting, and role-based access controls.
- Added transactional upload persistence and tests for saved evidence, pagination, permissions, missing records, and rollback.

## PT-04: Investigation-state APIs

- Added New, Investigating, Escalated, Resolved, and False Positive investigation states with validated transitions.
- Added endpoints for investigation details, state updates, escalation, analyst notes, and state/note history.
- Added authenticated user attribution, timestamps, before/after values, and immutable audit history.
- Added stale-update protection and tests for valid transitions, invalid transitions, notes, history, and unauthorized requests.

## PT-05: Incident management v2

- Added eligible analyst assignment and support for multiple linked alerts while retaining the primary alert.
- Added incident timelines and audit records for assignment, status, linked alerts, and note changes.
- Added atomic resolution with required reasons/notes, resolver identity, timestamps, and matching linked-alert outcomes.
- Added reopening with a reason while preserving earlier resolution decisions.
- Added transition validation, version checks, authenticated lifecycle endpoints, and migration support for existing incidents.
- Added API, database, concurrency, and migration tests.

## Tests added and updated

- `test_correlation_schema.py`: Evidence constraints, duplicate links, and preservation of original records.
- `test_correlation_engine.py`: Entity matching, time-window boundaries, normalization, deterministic results, duplicates, and unrelated activity.
- `test_correlation_api.py`: Evidence persistence, pagination, permissions, invalid requests, upload rollback, cross-upload evidence, and duplicate prevention.
- `test_investigation_api.py`: State transitions, escalation, notes, actor attribution, immutable history, permissions, and stale updates.
- `test_incident_lifecycle_api.py`: Assignment, linked alerts, resolution, reopening, permissions, rollback, and history pagination without missing, repeated, or unrelated records.
- `test_sprint6_migrations.py`: Upgrade, rollback, and re-upgrade of existing data while preserving evidence.
- `test_workflow_concurrency.py`: Concurrent escalation, stale updates, alert linking, single-use authentication tokens, OTP attempt limits/resend cooldowns, and password-reset requests.
- Updated `test_jwt_refresh.py`: Required access-token claims, token purpose, and CSRF protection on refresh/logout even with bearer headers.
- `test_slack_dispatch.py`: HTTPS-only delivery, rejected redirects, and errors that conceal webhook secrets.
- Updated existing API, workflow, and note tests for required resolution/reopening details and retained note-deletion audit snapshots.
