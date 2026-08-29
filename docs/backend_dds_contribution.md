# Backend DDS Contribution

## Scope

This document records the backend architecture, service responsibilities, API surface, database schema, persistence behavior, and server-side data flow for the CyberShield SOC backend. It is intended for Sprint Review and DDS handoff evidence.

## Backend Architecture

The backend is a FastAPI application in `backend/app/main.py`. It exposes both root-level routes and `/api` aliases so the React frontend can call the same contracts through Vite proxy or direct API URLs.

Primary backend layers:

- `app/routers`: HTTP route handlers, request validation, role gates, response shaping, transaction boundaries.
- `app/schemas`: Pydantic request models and enum contracts for client input.
- `app/repositories`: database operations and JSON-safe serialization for persistent records.
- `app/models`: SQLAlchemy ORM models and database constraints.
- `app/parsers`: log-format detection and canonical event normalization.
- `app/detection`: deterministic rule engine, rule metadata, configurable thresholds, and alert contracts.
- `app/db`: SQLAlchemy session factory, Alembic metadata registration, and seed utilities.
- `app/security.py`: password hashing, JWT access tokens, refresh sessions, current-user loading, and role checks.
- `app/middleware/file_validation.py`: upload extension, MIME, size, empty-file, binary-content, and filename-sanitization validation.

## Service Responsibilities

### Application Startup and Security Headers

`app/main.py` configures FastAPI, CORS, CSRF validation for cookie-authenticated writes, security headers, router registration, health checks, and static frontend serving when `frontend/dist` exists.

Security controls include:

- CORS restricted to local frontend origins.
- Double-submit CSRF validation for browser cookie-authenticated write requests.
- `X-Content-Type-Options`, `X-Frame-Options`, referrer, opener, resource, permissions, cache, and optional HSTS headers.
- Duplicate route registration under `/api` for frontend compatibility.

### Upload and Parsing

`app/routers/upload.py` accepts log uploads from Admin and Analyst users. It validates file metadata/content, decodes UTF-8, parses supported formats, runs detection rules, and persists logs, alerts, and upload-batch metadata in one database transaction.

Supported formats:

- `.log`
- `.csv`
- `.txt`
- `.json`
- `.jsonl`

Upload persistence is append-only. Re-uploading the same file creates a new `upload_id`, which keeps refresh/history behavior deterministic and avoids overwriting prior evidence.

### Detection

`app/detection/engine.py` runs all active rules over normalized `LogRecord` objects. Detection Engine v2 exposes rule metadata and threshold configuration through `RuleConfig`.

Current rule set:

- `brute_force_login`
- `invalid_user_enumeration`
- `sudo_failure`
- `password_spraying`
- `credential_stuffing_success`
- `port_scan`

Rules can be configured with `DETECTION_RULE_CONFIG` and inspected through `GET /detection/rules` or `GET /api/detection/rules`.

### Alert Workflow

`app/routers/alerts.py` lists persistent alerts and allows Admin/Analyst users to update alert severity or workflow status. Viewers can read alerts but cannot mutate them.

Alert persistence happens during upload through `create_alerts_from_detection`, using deterministic detection output serialized into dashboard-compatible fields.

### Incident Workflow

`app/routers/incidents.py` handles incident creation, listing, retrieval, and updates.

Responsibilities:

- `POST /incidents`: creates one incident from an existing alert.
- `GET /incidents`: lists incidents with optional `status`, `priority`, `assigned_user_id`, and `limit` filters.
- `GET /incidents/{incident_id}`: retrieves one incident.
- `PATCH /incidents/{incident_id}`: updates assignment, title, description, priority, or status.

The repository layer enforces:

- The source alert must exist.
- Only one incident can exist per alert.
- Assigned users and audit users must exist when supplied.
- Escalating an alert to an incident changes the alert status to `ESCALATED`.
- Incident status transitions maintain `resolved_at` and `closed_at` timestamps.

### Analyst Notes

`app/routers/notes.py` supports incident-specific notes and workspace-wide note listing. Admin and Analyst users can create/update/delete notes; Viewers can read notes.

Notes include:

- `title`
- `body`
- normalized tags
- pinned/archive display flags
- author and incident references
- created/updated timestamps

### Authentication and RBAC

Authentication uses JWT access tokens plus database-backed refresh sessions. `require_roles(...)` gates protected routes by role.

Role model:

- `Admin`: user management, uploads, alerts, incidents, notes, dashboard reads.
- `Analyst`: uploads, alerts, incidents, notes, dashboard reads.
- `Viewer`: dashboard/log/alert/incident/note reads only.

## API Endpoint Summary

All protected endpoints require an authenticated user with the allowed role. Each endpoint is also mounted under `/api`.

| Endpoint | Method | Purpose | Roles |
| --- | --- | --- | --- |
| `/health` | GET | Service health check | Public |
| `/auth/login` | POST | Login and issue access/refresh tokens | Public |
| `/auth/refresh` | POST | Rotate refresh session and issue access token | Cookie + CSRF |
| `/auth/me` | GET | Return current user | Admin, Analyst, Viewer |
| `/auth/logout` | POST | Revoke refresh session and clear cookies | Auth cookie |
| `/upload` | POST | Validate, parse, detect, and persist uploaded logs | Admin, Analyst |
| `/upload/latest` | GET | Return most recent upload batch with logs/alerts | Admin, Analyst, Viewer |
| `/upload/history` | GET | Paginated upload-batch metadata | Admin, Analyst, Viewer |
| `/upload/batches/{upload_id}` | GET | Logs and alerts for one upload batch | Admin, Analyst, Viewer |
| `/upload/formats` | GET | Accepted upload formats and size limit | Admin, Analyst, Viewer |
| `/detection/rules` | GET | Active rule metadata and thresholds | Admin, Analyst, Viewer |
| `/alerts` | GET | List persistent alerts | Admin, Analyst, Viewer |
| `/alerts/{alert_id}` | PATCH | Update alert severity/status | Admin, Analyst |
| `/incidents` | POST | Create incident from alert | Admin, Analyst |
| `/incidents` | GET | List incidents | Admin, Analyst, Viewer |
| `/incidents/{incident_id}` | GET | Retrieve incident | Admin, Analyst, Viewer |
| `/incidents/{incident_id}` | PATCH | Update incident workflow fields | Admin, Analyst |
| `/incidents/{incident_id}/notes` | GET | List notes for an incident | Admin, Analyst, Viewer |
| `/incidents/{incident_id}/notes` | POST | Add incident note | Admin, Analyst |
| `/notes` | GET | List workspace notes | Admin, Analyst, Viewer |
| `/notes/{note_id}` | PATCH | Update note fields | Admin, Analyst |
| `/notes/{note_id}` | DELETE | Delete note | Admin, Analyst |
| `/users/roles` | GET | List role options | Admin |
| `/users` | GET | List users | Admin |
| `/users` | POST | Create user | Admin |
| `/users/{user_id}/role` | PATCH | Change user role | Admin |
| `/users/{user_id}/active` | PATCH | Activate/deactivate user | Admin |

## Database Schema Summary

### `roles`

Stores RBAC roles. Seeded roles are Admin, Analyst, and Viewer.

Important fields:

- `id`
- `name`
- `description`
- `created_at`

### `users`

Stores user accounts and role assignments.

Important fields:

- `id`
- `role_id`
- `username`
- `email`
- `password_hash`
- `full_name`
- `is_active`
- `created_at`
- `updated_at`

### `auth_sessions`

Stores refresh-token session hashes, never plaintext tokens.

Important fields:

- `id`
- `user_id`
- `token_hash`
- `created_at`
- `expires_at`
- `revoked_at`

### `upload_batches`

Authoritative upload metadata table. One row represents one uploaded file.

Important fields:

- `upload_id`
- `source_filename`
- `source_format`
- `mime_type`
- `size_bytes`
- `total_lines`
- `parsed_entries`
- `skipped_lines`
- `stored_entries`
- `stored_alerts`
- `uploaded_at`

### `logs`

Stores normalized event rows created from parsed upload content.

Important fields:

- `id`
- `upload_id`
- `source_filename`
- `source_format`
- `line_number`
- `event_timestamp`
- `ip_address`
- `username`
- `event_type`
- `status`
- `severity`
- `raw_message`
- `parsed_data`
- `ingested_at`

Constraint:

- `(upload_id, line_number)` is unique, which prevents duplicate line records within one upload but allows independent re-uploads.

### `alerts`

Stores deterministic detection results.

Important fields:

- `id`
- `upload_id`
- `rule`
- `title`
- `severity`
- `status`
- `source_ip`
- `username`
- `event_count`
- `time_window_seconds`
- `first_seen`
- `last_seen`
- `description`
- `matched_line_numbers`
- `created_at`
- `updated_at`

### `incidents`

Stores investigation records created from alerts.

Important fields:

- `id`
- `source_alert_id`
- `assigned_user_id`
- `created_by_user_id`
- `updated_by_user_id`
- `title`
- `description`
- `priority`
- `status`
- `opened_at`
- `resolved_at`
- `closed_at`
- `created_at`
- `updated_at`

Constraints:

- One incident per source alert.
- Priority must be `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`.
- Status must be `OPEN`, `INVESTIGATING`, `RESOLVED`, or `FALSE_POSITIVE`.

### `notes`

Stores analyst notes attached to incidents.

Important fields:

- `id`
- `incident_id`
- `author_user_id`
- `title`
- `body`
- `tags`
- `pinned`
- `archived`
- `created_at`
- `updated_at`

## Persistence Behavior

Upload writes are transactional. `POST /upload` stores parsed logs, generated alerts, and upload-batch metadata together. If any database write fails, the route rolls back the full upload transaction and returns `DATABASE_WRITE_ERROR`.

Incident writes are transactional. Creating an incident updates both the new incident row and the source alert lifecycle in the same transaction. Duplicate incidents for the same alert return `409`.

Note writes are transactional. Note creation validates the incident and author, enforces the note limit, and rolls back on failure.

Authentication refresh sessions store only hashed opaque tokens. Logout and refresh rotation update `auth_sessions` rather than storing raw credentials.

## Server-Side Data Flow

### Upload-to-Detection Flow

1. Client uploads a file to `POST /upload`.
2. File validation checks extension, MIME type, size, non-empty content, binary content, and safe filename.
3. The parser detects format and normalizes events into canonical fields.
4. The route maps parsed entries into `LogRecord` objects.
5. Detection Engine v2 runs enabled rules with configured thresholds.
6. The repository layer persists `logs`, `alerts`, and `upload_batches`.
7. The response returns upload metadata, parsing summary, entries, skipped lines, and persistent alerts.

### Investigation Flow

1. Analyst reviews alerts from `GET /alerts`.
2. Analyst creates an incident with `POST /incidents`.
3. Backend validates the alert, prevents duplicate incident creation, and escalates the alert status.
4. Analyst updates incident status/priority/assignment through `PATCH /incidents/{incident_id}`.
5. Analyst adds evidence and review notes through `POST /incidents/{incident_id}/notes`.
6. Viewer users can read alerts, incidents, and notes without mutating records.

## Backend Accuracy Review

Reviewed DDS descriptions against the current backend implementation on August 29, 2026.

Accuracy notes:

- Upload support is broader than the older Sprint 2 summary; the backend now accepts `.log`, `.csv`, `.txt`, `.json`, and `.jsonl`.
- Alerts are persistent PostgreSQL records, not in-memory-only records.
- Upload history is backed by `upload_batches`, not derived only from `logs`.
- Incident status supports `FALSE_POSITIVE`; `CLOSED` is no longer part of the current incident status enum.
- Detection rules expose metadata and configurable thresholds through Detection Engine v2.
- Admin/Analyst/Viewer seed definitions are present, with account creation controlled by environment-provided passwords.

Verification evidence:

- `python scripts/check_db.py`: database connection successful.
- `python -m alembic upgrade head`: applied `f3b1c9e4a002_create_upload_batches_table`.
- `python -m pytest tests\test_api.py -q`: 26 passed, 1 warning.
- `python -m pytest backend/tests/test_detection_engine_v2_config.py backend/tests/test_seed_validation.py -q`: 4 passed, 1 warning.

Remaining documentation note:

- `docs/sprint2_documentation_summary.md` is historical and contains older statements about supported file types and alert persistence. Treat this DDS document and the current backend tests as the up-to-date backend handoff source.
