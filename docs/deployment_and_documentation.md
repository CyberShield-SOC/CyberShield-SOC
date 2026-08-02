# Deployment and Documentation Checklist

Use this checklist before a Sprint demo or deployment handoff. It covers clean-environment setup, environment variables, migrations, seeded accounts, and automated verification.

## Clean Environment Install

Prerequisites:

- Docker Desktop with the Docker engine running
- Python 3.13
- Node.js 24 and npm
- Git

From a fresh clone, create the local environment file:

```powershell
Copy-Item .env.example .env
```

Edit `.env` and replace every `replace_me` value before starting the app. Do not commit `.env`.

Create the backend virtual environment:

```powershell
Set-Location backend
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
Set-Location ..
```

Install frontend dependencies:

```powershell
Set-Location frontend
npm ci
Set-Location ..
```

If npm is using an IDE-managed or otherwise locked cache, keep the install
inside the repository by passing a local cache path:

```powershell
Set-Location frontend
npm ci --cache ..\.tools\npm-cache
Set-Location ..
```

Start the complete Windows demo environment:

```powershell
.\start.ps1
```

The script validates `.env`, backend dependencies, and frontend dependencies; starts PostgreSQL; applies migrations; seeds the initial Admin user; starts FastAPI on `http://127.0.0.1:3000`; and starts Vite on `https://127.0.0.1:5173` with a self-signed local certificate.

## Environment Variables

Root `.env` variables:

| Variable | Required | Used by | Notes |
|---|---:|---|---|
| `POSTGRES_DB` | Yes | Docker Compose | PostgreSQL database name. |
| `POSTGRES_USER` | Yes | Docker Compose | Local database user. |
| `POSTGRES_PASSWORD` | Yes | Docker Compose | Local database password. Use a non-shared local value. |
| `POSTGRES_PORT` | Yes | Docker Compose | Host port mapped to PostgreSQL container port `5432`. |
| `DATABASE_URL` | Yes | FastAPI, Alembic, seed script | SQLAlchemy URL. For this stack, use `postgresql+psycopg://user:password@localhost:5432/cybershield`. |
| `AUTH_SESSION_TTL_MINUTES` | No | FastAPI auth | Defaults to `60`; valid range is 5 to 1440. |
| `AUTH_REMEMBER_TTL_DAYS` | No | FastAPI auth | Defaults to `7`; valid range is 1 to 90. |
| `AUTH_COOKIE_SECURE` | No | FastAPI auth | Use `false` for local HTTP. Use `true` only when serving over HTTPS. |
| `JWT_SECRET_KEY` | Yes | FastAPI auth | Long random signing key for JWT access tokens. Generate with `python -c "import secrets; print(secrets.token_urlsafe(64))"`. |
| `JWT_ACCESS_TTL_MINUTES` | No | FastAPI auth | Defaults to `10`; valid range is 1 to 60. |
| `CYBERSHIELD_ADMIN_USERNAME` | No | Seed script | Initial Admin username; defaults to `admin`. |
| `CYBERSHIELD_ADMIN_EMAIL` | No | Seed script | Initial Admin email; defaults to `admin@cybershield.io`. |
| `CYBERSHIELD_ADMIN_PASSWORD` | Yes for first Admin | Seed script | Creates the initial Admin when no matching username exists. Set a strong local password. |

Frontend environment variables:

| Variable | Required | Notes |
|---|---:|---|
| `VITE_API_BASE_URL` | No | Copy `frontend/.env.example` to `frontend/.env.local` only when overriding the frontend API base URL. Use `/api` for the Vite proxy. Do not put secrets in `VITE_*` variables because they are bundled into browser code. |

## Migrations

Alembic migrations live in `backend/alembic/versions`.

Apply all migrations from the repository root on Windows:

```powershell
Set-Location backend
.\.venv\Scripts\python.exe -m alembic upgrade head
Set-Location ..
```

The same command is run automatically by `start.ps1` before the backend server starts.

## Seeded Accounts and Roles

The seed script is `backend/app/db/seed.py`.

Run it after migrations:

```powershell
Set-Location backend
.\.venv\Scripts\python.exe -m app.db.seed
Set-Location ..
```

Seeded roles:

| Role | Purpose |
|---|---|
| `Admin` | Manages users, roles, and CyberShield system settings. |
| `Analyst` | Reviews alerts, investigates incidents, and writes notes. |
| `Viewer` | Views dashboards and security records without editing them. |

The initial Admin account is created only when `CYBERSHIELD_ADMIN_PASSWORD` is set and no user exists with `CYBERSHIELD_ADMIN_USERNAME`.

## Automated Verification

Backend checks:

```powershell
docker compose up -d --wait database
Set-Location backend
.\.venv\Scripts\python.exe -m alembic upgrade head
.\.venv\Scripts\python.exe -m pytest tests -q -p no:cacheprovider
Set-Location ..
```

Frontend checks:

```powershell
Set-Location frontend
npm test
npm run build
Set-Location ..
```

GitHub Actions runs the same backend migration/test flow and frontend test/build flow in `.github/workflows/ci.yml`.

## Validation Record

Last validated on August 2, 2026 from the repository root on Windows PowerShell.

| Sprint item | Command or check | Result |
|---|---|---|
| DEP-1 clean install | `backend\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt` | Passed; all backend requirements installed or already satisfied. |
| DEP-1 clean install | `npm ci --cache ..\.tools\npm-cache` from `frontend/` | Passed; 41 packages installed, 0 vulnerabilities. |
| DEP-2 migrations | `.\.venv\Scripts\python.exe -m alembic upgrade head` from `backend/` | Passed; database upgraded to latest head. |
| DEP-2 seeded accounts | `.\.venv\Scripts\python.exe -m app.db.seed` from `backend/` | Passed; default roles already existed and no duplicate seed data was created. |
| DEP-3 backend tests | `.\.venv\Scripts\python.exe -m pytest tests -q -p no:cacheprovider` from `backend/` | Passed; 242 tests passed, 3 warnings. |
| DEP-3 frontend tests | `npm test` from `frontend/` | Passed; 97 tests passed. |
| DEP-3 frontend build | `npm run build` from `frontend/` | Passed; Vite production build completed successfully. |

Notes:

- This shell did not expose `npm` or `docker` on `PATH`; validation used the repository's portable Node.js runtime under `.tools/node/node-v24.18.1-win-x64`, and the configured PostgreSQL database was already reachable for migrations and tests.
- The first `npm ci` attempt failed against an IDE-managed cache outside the repository. Rerunning with `--cache ..\.tools\npm-cache` avoided that machine-specific cache permission issue.

## Demo Readiness

Before demonstrating:

- Confirm Docker Desktop is running.
- Confirm `.env` has no `replace_me` placeholders.
- Confirm `frontend/node_modules` exists.
- Run `.\start.ps1` from the repository root.
- Open `https://127.0.0.1:5173` for the SOC UI and accept the one-time self-signed certificate warning.
- Open `http://127.0.0.1:3000/docs` for the backend API docs.
- Use the Admin credentials from `.env` for the first login.
