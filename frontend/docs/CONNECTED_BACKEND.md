# Run the connected CyberShield app

The React frontend and FastAPI backend run as separate local processes. PostgreSQL must be healthy before FastAPI starts.

Prerequisites: Node.js/npm, Python with `venv`, and Docker Desktop or another reachable PostgreSQL 17 instance.

## One-time setup

From the repository root, create the local backend environment:

```powershell
Copy-Item .env.example .env
notepad .env
```

Replace every `replace_me` value. Keep `AUTH_COOKIE_SECURE=false` only for local HTTP development; production HTTPS must set it to `true`.

Start PostgreSQL:

```powershell
docker compose up -d --wait database
```

Prepare and seed FastAPI:

```powershell
Set-Location backend
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m alembic upgrade head
.\.venv\Scripts\python.exe -m app.db.seed
Set-Location ..
```

Install the locked frontend dependencies:

```powershell
Set-Location frontend
npm.cmd install
Set-Location ..
```

## Start the application

From the repository root:

```powershell
.\start.ps1
```

You can also use the VS Code task **Start CyberShield SOC (both servers)**.

- Frontend: `http://127.0.0.1:5173`
- API health: `http://127.0.0.1:3000/health`
- API documentation: `http://127.0.0.1:3000/docs`

The checked-in `frontend/.env.example` uses the same-origin `/api` contract. The ignored `frontend/.env.local` can enable it locally. Restart Vite after changing frontend environment values.

## Test role access

1. Sign in with the Admin email or username and the password configured before seeding.
2. Open **Users** and create development-only Analyst and Viewer accounts.
3. Test each account in a separate private window or browser profile so one role's cookie does not replace another session.
4. Confirm Analyst can investigate but cannot open Users.
5. Confirm Viewer can read operational records but cannot perform mutations.
6. Disable the test accounts or reset their passwords when testing is complete.

## Verification

```powershell
Set-Location frontend
npm.cmd test
npm.cmd run build

Set-Location ..\backend
.\.venv\Scripts\python.exe -m pytest tests -q -p no:cacheprovider
```

## Production deployment boundary

1. Provide PostgreSQL and inject `DATABASE_URL` plus the `CYBERSHIELD_ADMIN_*` values through the host's secret manager.
2. Set `AUTH_COOKIE_SECURE=true` and serve the browser and API over HTTPS.
3. Run `python -m alembic upgrade head`, then run `python -m app.db.seed` once for the initial Admin.
4. Build `frontend/` with `npm ci` and `npm run build`.
5. Serve `frontend/dist/` and reverse-proxy `/api` to FastAPI on the same HTTPS origin, or configure an explicitly allow-listed API origin and matching CORS policy.
6. Require the GitHub Actions workflow to pass before merging to `main`.

Do not commit `.env`, database files, test-account passwords, session cookies, tokens, or production evidence.
