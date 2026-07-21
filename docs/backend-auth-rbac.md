# Backend Authentication and RBAC Handoff

## Authentication Strategy

CyberShield uses short-lived JWT access tokens backed by a rotating,
DB-persisted refresh token. `POST /auth/login` returns a signed JWT
(`access_token`) for the client to send as `Authorization: Bearer <token>` on
every protected request, and separately installs an opaque refresh token in an
HttpOnly, SameSite=Strict browser cookie. Only the SHA-256 digest of the
refresh token is stored in `auth_sessions`; the JWT itself is never persisted
server-side — it's verified purely by signature and expiry.

**Every protected route, including `GET /auth/me`, requires the Bearer
header.** The refresh cookie by itself no longer grants API access; its only
purpose is minting new access tokens via `POST /auth/refresh`, which rotates
it (revokes the presented token, issues a new one) each time it's used.

Token lifetimes are controlled by:

```text
JWT_SECRET_KEY=<long random value>     # required; signs and verifies access tokens
JWT_ACCESS_TTL_MINUTES=10              # access token lifetime (default 10)
AUTH_SESSION_TTL_MINUTES=60            # refresh token lifetime, non-"remember me"
AUTH_REMEMBER_TTL_DAYS=7               # refresh token lifetime, "remember me"
```

Expired, missing, malformed, or tampered access tokens return `401
Unauthorized`. Authenticated users without the required role return `403
Forbidden`.

**Accepted trade-off:** deactivating a user (`PATCH /users/{id}/active`) is an
instant kill-switch — `current_user()` checks `is_active` on the database on
every request, independent of the JWT's own expiry. Resetting a user's
password and the explicit "revoke sessions" action, however, only revoke the
*refresh* token — they block that user's next `/auth/refresh` call, but any
already-issued, unexpired access token keeps working until it naturally
expires (bounded to `JWT_ACCESS_TTL_MINUTES`). This is the standard trade-off
of short-lived JWTs over fully stateful sessions, deliberately accepted here
in exchange for stateless, DB-free verification of the access token itself.
See `backend/tests/test_full_contract.py::test_admin_user_management_lifecycle`
for the exact behavior this guarantees.

## Role Matrix

| Action | Admin | Analyst | Viewer |
| --- | --- | --- | --- |
| View dashboard/logs/alerts/incidents/notes | Allow | Allow | Allow |
| Upload/import logs | Allow | Allow | Deny |
| Create/update incidents | Allow | Allow | Deny |
| Add analyst notes | Allow | Allow | Deny |
| Manage users and roles | Allow | Deny | Deny |

## API Contract

### `POST /auth/login`

Request:

```json
{
  "username": "analyst1",
  "password": "user-entered-password"
}
```

Success:

```json
{
  "success": true,
  "access_token": "<jwt>",
  "token_type": "bearer",
  "expires_in": 600,
  "user": {
    "id": 4,
    "username": "analyst1",
    "email": "analyst1@example.test",
    "full_name": "Analyst One",
    "is_active": true,
    "role": "Analyst"
  }
}
```

Also sets the HttpOnly refresh-token cookie and its paired non-secret CSRF
cookie. `access_token` here is the short-lived JWT — never the refresh token.

Failure:

```json
{
  "detail": "Invalid username or password"
}
```

### `POST /auth/refresh`

Reads the refresh cookie (no request body). Requires the matching
`X-CSRF-Token` header, since this is the browser's only remaining
cookie-authenticated endpoint besides logout. Rotates the refresh token
(revokes the presented one, issues and cookies a new one) and returns a fresh
access token with the same shape as `LoginResponse` minus the login-specific
fields:

```json
{
  "success": true,
  "access_token": "<new jwt>",
  "token_type": "bearer",
  "expires_in": 600,
  "user": { "...": "..." }
}
```

`401` if the cookie is missing, expired, or already revoked (including replay
of a refresh token that was already rotated away).

### `GET /auth/me`

Header (required — the refresh cookie alone is not sufficient):

```text
Authorization: Bearer <access_token>
```

Success:

```json
{
  "success": true,
  "user": {
    "id": 4,
    "username": "analyst1",
    "email": "analyst1@example.test",
    "full_name": "Analyst One",
    "is_active": true,
    "role": "Analyst"
  }
}
```

### `POST /auth/logout`

Revokes the refresh token found in the cookie (idempotent — a missing or
already-revoked token still succeeds), expires both browser cookies, and
returns a no-store response. Does not invalidate any already-issued access
token; those remain valid until they naturally expire (see the accepted
trade-off above). The frontend clears its in-memory access token locally
regardless of the response.

## Endpoint Protection Inventory

| Endpoint | Protection | Allowed Roles |
| --- | --- | --- |
| `GET /health` | Public | Anyone |
| `POST /auth/login` | Public | Anyone |
| `POST /auth/refresh` | Refresh cookie + CSRF | Anyone with a valid refresh token |
| `GET /auth/me` | Bearer JWT required | Admin, Analyst, Viewer |
| `POST /auth/logout` | Refresh cookie + CSRF (idempotent) | Anyone |
| `GET /alerts` | Role restricted | Admin, Analyst, Viewer |
| `PATCH /alerts/{alert_id}` | Role restricted | Admin, Analyst |
| `POST /upload` | Role restricted | Admin, Analyst |
| `GET /upload/latest` | Role restricted | Admin, Analyst, Viewer |
| `GET /upload/formats` | Role restricted | Admin, Analyst, Viewer |
| `GET /incidents` | Role restricted | Admin, Analyst, Viewer |
| `GET /incidents/{incident_id}` | Role restricted | Admin, Analyst, Viewer |
| `POST /incidents` | Role restricted | Admin, Analyst |
| `PATCH /incidents/{incident_id}` | Role restricted | Admin, Analyst |
| `GET /incidents/{incident_id}/notes` | Role restricted | Admin, Analyst, Viewer |
| `POST /incidents/{incident_id}/notes` | Role restricted | Admin, Analyst |
| `GET /notes` | Role restricted | Admin, Analyst, Viewer |
| `PATCH /notes/{note_id}` | Role restricted | Admin, Analyst |
| `DELETE /notes/{note_id}` | Role restricted | Admin, Analyst |
| `GET /users/roles` | Role restricted | Admin |
| `GET /users` | Role restricted | Admin |
| `POST /users` | Role restricted | Admin |
| `PATCH /users/{user_id}/role` | Role restricted | Admin |
| `PATCH /users/{user_id}/active` | Role restricted | Admin |

Routers are also exposed under `/api` for frontend compatibility, so the same
permissions apply to `/api/...` paths.

Authentication responses are marked `Cache-Control: no-store`. API responses
also deny framing, disable content-type sniffing, use a strict referrer policy,
and restrict browser permissions. In production, enable secure cookies with
`AUTH_COOKIE_SECURE=true`, terminate TLS before the service, and rate-limit the
public login endpoint at the edge.

## Setup

Run migrations:

```powershell
cd backend
alembic upgrade head
```

Seed roles and optional first Admin:

```powershell
cd backend
python -m app.db.seed
```

The first Admin password must come from local environment variable
`CYBERSHIELD_ADMIN_PASSWORD`. Do not commit real passwords or tokens.
