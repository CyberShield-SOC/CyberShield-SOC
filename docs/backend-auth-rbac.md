# Backend Authentication and RBAC Handoff

## Authentication Strategy

CyberShield uses database-backed opaque sessions instead of JWTs. `POST
/auth/login` returns a random token for API clients and also installs it in an
HttpOnly, SameSite=Strict browser cookie. Only the SHA-256 digest is stored in
`auth_sessions`, so raw tokens are not persisted. The React application uses
the cookie session and never stores the returned token.

Session lifetime is controlled by:

```text
AUTH_SESSION_TTL_MINUTES=60
```

Expired, missing, revoked, or invalid tokens return `401 Unauthorized`.
Authenticated users without the required role return `403 Forbidden`.

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
  "access_token": "opaque-session-token",
  "token_type": "bearer",
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

Failure:

```json
{
  "detail": "Invalid username or password"
}
```

### `GET /auth/me`

Header:

```text
Authorization: Bearer <access_token>
```

Browser clients may omit this header and use the HttpOnly session cookie. A
cookie-authenticated state-changing request must copy the non-secret CSRF
cookie into `X-CSRF-Token`.

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

Revokes the current cookie or bearer session, expires the browser cookies, and
returns a no-store response. The frontend redirects to login; it has no local
authentication token to remove.

## Endpoint Protection Inventory

| Endpoint | Protection | Allowed Roles |
| --- | --- | --- |
| `GET /health` | Public | Anyone |
| `POST /auth/login` | Public | Anyone |
| `GET /auth/me` | Authenticated | Admin, Analyst, Viewer |
| `POST /auth/logout` | Authenticated | Admin, Analyst, Viewer |
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
