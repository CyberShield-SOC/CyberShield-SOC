# Backend Authentication and RBAC Handoff

## Authentication Strategy

CyberShield uses database-backed opaque bearer sessions instead of JWTs.
`POST /auth/login` returns a random bearer token. Only the SHA-256 digest is
stored in `auth_sessions`, so raw tokens are not persisted.

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

Revokes the current bearer session. The frontend should then remove the local
token and redirect to login.

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
| `GET /users/roles` | Role restricted | Admin |
| `GET /users` | Role restricted | Admin |
| `POST /users` | Role restricted | Admin |
| `PATCH /users/{user_id}/role` | Role restricted | Admin |
| `PATCH /users/{user_id}/active` | Role restricted | Admin |

Routers are also exposed under `/api` for frontend compatibility, so the same
permissions apply to `/api/...` paths.

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
