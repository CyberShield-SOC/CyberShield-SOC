# Sprint 7: ingestion, custom rules, and authentication review

## S7-02.2, S7-02.3, S7-02.5 — Collector ingestion

`POST /api/ingest` (also `/ingest`) accepts JSON containing:

```json
{
  "source_name": "web-auth-collector",
  "source_type": "agent",
  "source_host": "web-01",
  "filename": "auth.log",
  "content": "Jun 14 14:00:00 web-01 useradd[1]: new user: name=mallory, UID=2001"
}
```

Send `Authorization: Bearer <access_token>` from an authenticated Admin or
Analyst account. Use the existing login and two-factor flow to obtain the
access token and refresh flow to renew it. Viewer and unknown roles cannot
ingest. This endpoint does not introduce a shared collector secret or bypass
two-factor authentication. Do not embed account credentials in collector code.

`source_type` is `api` (default), `agent`, `file`, or `syslog`. `source_host`
is optional. `filename` defaults to `events.jsonl` and selects the existing
log parser; supported suffixes are `.log`, `.txt`, `.csv`, `.json`, `.jsonl`.
Content is a text string, limited to 10 Mi characters, additionally subject
to the existing 50 MiB UTF-8 file limit. Blank and binary content is rejected.
Source name and host are supplied by the collector, not independently verified.
`ingested_by` comes from the authenticated account and cannot be supplied by clients.

Collected content runs through the same parsing, enrichment, built-in/custom
detection, cooldown, correlation, and storage pipeline as `/upload`. A successful
response has the existing upload response shape, including stored log/alert
counts. Batch responses and upload history include `source_name`, `source_type`,
`source_host`, and `ingested_by`. File uploads record their filename, `file`
source type, and authenticated uploader. Existing batches retain null provenance.
Each submission creates a new batch; retries are not idempotent.

Apply the additive schema migration before starting the updated backend:

```powershell
cd backend
.\.venv\Scripts\python.exe -m alembic upgrade head
```

No migration is applied automatically by the API. Database pipeline errors
roll back the batch and its events/alerts. External notifications retain the
existing synchronous dispatch behavior and are not a transactional outbox.

## S7-03.1 and S7-03.2 — Custom rule review and fixes

- Conditions use AND semantics and the existing field/operator allowlists.
- Invalid ports, empty list values, blank values, malformed timestamp boundaries,
  and invalid or empty time ranges are rejected before persistence.
- HH:MM ranges retain minute precision, include the start, and exclude the end;
  overnight ranges wrap midnight. The default zone is UTC. Named IANA zones
  account for daylight saving time.
- Timestamp parsing normalizes aware values to UTC and treats naive values as UTC.
- Alert windows are measured from the first event, preventing a chain of closely
  spaced matches from extending one window indefinitely. Events exactly at the
  configured duration remain in the bucket for compatibility.
- An empty persisted condition list cannot match every event.
- Rule insertion happens inside the retry savepoint so a unique ID collision
  cannot abort the outer transaction before the savepoint exists.
- Partial action updates preserve other actions. Nullable tactic and DSL values
  can be cleared explicitly; required update fields reject explicit nulls.
- A nested `create_alert` configuration with `enabled: false` is respected.

## S7-05.1 — Role and session review

The bearer dependency verifies the JWT signature, required claims, expiry, and
token type, then loads the user and role from the database. Role demotion applies
to an already issued token; missing/deactivated users are rejected. Refresh
rotation locks the user and session, rejects expired/revoked sessions, and revokes
the previous refresh token. Cookie refresh/logout writes require CSRF validation.

Access tokens remain stateless: logout, password reset, and explicit session
revocation revoke refresh sessions but do not immediately invalidate an issued
access token while its user remains active. Such tokens expire after the configured
access TTL (10 minutes by default). Immediate access-token revocation would require
an additional session/version check and is not introduced by these ingestion changes.

Regression coverage: `test_ingestion.py`, `test_custom_condition_rule.py`,
`test_custom_rule_schemas.py`, `test_custom_rule_repository.py`, plus existing
authentication and refresh suites. The collector integration test requires
PostgreSQL at the latest Alembic head.

## Submission verification — 2026-10-24

**Ready for submission for the six listed tasks: 307 tests passed, no failures
or skips in the selected 18 test modules.** Verification used PostgreSQL 17 in
an isolated Docker container and disposable schemas. The full migration chain
was applied to a clean schema before the tests. Development data was unchanged;
the target environment still needs `alembic upgrade head` before using this code.

| Task | Verified evidence |
| --- | --- |
| S7-02.2 | Admin/Analyst permissions, missing-token and Viewer rejection, and ingestion using a real signed bearer token backed by a persisted user |
| S7-02.3 | Source metadata and uploader attribution persist and can be retrieved; migration preserves legacy batches through upgrade, downgrade, and reupgrade |
| S7-02.5 | Collector input passes through the real parser/detection/storage pipeline and produces a persisted `new_account_created` alert |
| S7-03.1 | Field/operator/value validation, timezone and minute-level time matching, and update validation tests |
| S7-03.2 | Bounded match windows, partial action updates, nullable-field clearing, and a real PostgreSQL unique-ID collision that leaves the outer transaction usable |
| S7-05.1 | Authentication/RBAC, JWT validation and refresh, privilege escalation guards, two-factor login, password reset, and session-related contract tests |

The first integration run exposed an outdated upload test that supplied an
unpersisted fake user. Its setup now creates a real account and checks uploader
attribution, preserving the new foreign-key constraint. The complete selected
suite passed after this correction. `git diff --check` also passed.

The run emitted one existing Starlette deprecation warning about the name of
the HTTP 422 constant. It did not affect test results. The stateless access-token
revocation behavior documented above remains unchanged.

To repeat the verified suite against a dedicated test database at migration head,
set `DATABASE_URL`, `JWT_SECRET_KEY`, and `OTP_SECRET`, then run from `backend`:

```powershell
$testFiles = @(
  'tests/test_ingestion.py', 'tests/test_ingestion_migration.py',
  'tests/test_custom_condition_rule.py', 'tests/test_custom_rule_schemas.py',
  'tests/test_custom_rule_repository.py', 'tests/test_custom_rule_actions.py',
  'tests/test_auth_rbac.py', 'tests/test_jwt_refresh.py',
  'tests/test_rbac_privilege_escalation.py', 'tests/test_two_factor_auth.py',
  'tests/test_password_reset.py', 'tests/test_detection.py',
  'tests/test_detection_edge_cases.py', 'tests/test_detection_v2_upload.py',
  'tests/test_upload_txt_and_security.py', 'tests/test_full_contract.py',
  'tests/test_db_persistence.py', 'tests/test_sprint6_migrations.py'
)
.\.venv\Scripts\python.exe -m pytest @testFiles -p no:cacheprovider -q
```
