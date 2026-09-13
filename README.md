# CyberShield SOC

AI-Powered Log Monitoring and Threat Detection Platform

## Overview

CyberShield SOC is a full security-operations platform: a FastAPI backend that ingests and parses security logs, runs them through a rule-based detection engine, and persists logs, alerts, incidents, and analyst notes in PostgreSQL; and a React/Vite SOC dashboard for upload, investigation, incident workflows, and administration. Authentication uses JWT access tokens, refresh-token sessions, email-based two-factor verification, and role-based access control (Admin, Analyst, Viewer).

## Detection Rules

The `DetectionEngine` (`backend/app/detection/engine.py`) runs every enabled rule against each uploaded batch of parsed log entries. Rules are configurable per-deployment (`DETECTION_RULE_CONFIG`) and, for the built-in set below, also live-configurable by an Admin/Analyst through `GET`/`PATCH /detection/rules` without a restart. Analysts can additionally author custom rules at runtime through the Rule Builder (`POST/PATCH/DELETE /custom-rules`), which run alongside these built-ins.

| Rule | Severity | Detects |
| --- | --- | --- |
| `brute_force_login` | High | Repeated failed login attempts from one source IP in a short window |
| `invalid_user_enumeration` | Medium | One source IP trying several distinct usernames — account enumeration |
| `sudo_failure` | Medium | Repeated failed privilege-escalation (sudo) attempts by one user or source |
| `password_spraying` | High | One account receiving failed logins from many distinct source IPs |
| `credential_stuffing_success` | High | A failed-login burst from one IP immediately followed by a successful login — likely takeover |
| `port_scan` | Medium | A burst of port-scan events from one source IP |
| `multi_ip_successful_login` | Medium | One account with successful logins from several distinct source IPs in a short window — shared/compromised credential use |
| `sudo_after_login` | Medium | A successful login immediately followed by successful privilege escalation for the same account |

Sample normal and suspicious log fixtures for each rule live under `sample-logs/cybershield-rule-tests/` and `sample-logs/kk_normal.csv` / `sample-logs/kk_suspicious.csv`, exercised by `backend/tests/test_detection.py` and `backend/tests/test_kapil_sprint5_rules.py`.

## One-time local setup

Install these prerequisites before continuing:

- Docker Desktop with the Docker engine running
- Python 3.13
- Node.js 24 and npm

For the deployment/demo checklist, environment variable reference, migration commands, seeded account details, and verification commands, see [`docs/deployment_and_documentation.md`](docs/deployment_and_documentation.md).

For Kapil's Sprint 5 detection rules, sample logs, ML evaluation plan, and deployment verification checklist, see [`docs/kapil_sprint5_dds.md`](docs/kapil_sprint5_dds.md).

From the repository root, create the local environment file:

```powershell
Copy-Item .env.example .env
```

On macOS or Linux, use:

```bash
cp .env.example .env
```

Open `.env` and replace every `replace_me` value. Use a local-only database password and a strong initial Admin password. The `.env` file is ignored by Git and must never be committed. `frontend/.env.local` is optional; browser code must not contain secrets because all `VITE_*` values are public.

Install the backend dependencies on Windows:

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
cd ..
```

On macOS or Linux, replace the backend setup commands with:

```bash
cd backend
python3 -m venv .venv
./.venv/bin/python -m pip install -r requirements.txt
cd ..
```

Install the frontend dependencies:

```bash
cd frontend
npm install
cd ..
```

## Start the complete application

On Windows, open the repository root in VS Code, ensure Docker Desktop is running, and select **Terminal > Run Task > Start CyberShield SOC (both servers)**.

The startup task runs `start.ps1`, which:

1. Validates the local `.env`, backend virtual environment, and frontend dependencies.
2. Starts the PostgreSQL container and waits for it to become healthy.
3. Applies Alembic database migrations and creates the configured initial Admin when needed.
4. Starts FastAPI on `http://127.0.0.1:3000` and Vite on `http://127.0.0.1:5173`.
5. Opens the application in the browser.

The VS Code startup task is currently Windows-specific. On macOS or Linux, start PostgreSQL and prepare the database from the repository root:

```bash
docker compose up -d --wait database
cd backend
./.venv/bin/python -m alembic upgrade head
./.venv/bin/python -m app.db.seed
./.venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 3000
```

Then open a second terminal and start the frontend:

```bash
cd frontend
npm run dev -- --host 127.0.0.1
```

To verify the local PostgreSQL-backed backend on Windows:

```powershell
docker compose up -d --wait database
cd backend
.\.venv\Scripts\python.exe -m alembic upgrade head
.\.venv\Scripts\python.exe scripts\check_db.py
.\.venv\Scripts\python.exe -m pytest tests -q -p no:cacheprovider
```

Backend tests require the configured PostgreSQL database and current Alembic schema. They fail fast with setup instructions when PostgreSQL is unavailable or stale; PostgreSQL-specific schema types are never replaced with an SQLite fallback.

## Run the Standalone Parser Script

`parser/log_parser.py` is a legacy standalone CLI utility kept for quick, dependency-free parsing of a single log file outside the running application. The live backend uses its own parser (`backend/app/parsers/`), not this script.

```bash
python parser/log_parser.py sample-logs/auth.log
```

## Run the Backend API

If you are not using the complete startup task, install backend dependencies:

```bash
pip install -r backend/requirements.txt
```

Run the server:

```bash
cd backend
python main.py
```

Open:

- Frontend dashboard: `http://localhost:5173` (with Vite dev server running)
- API docs: `http://localhost:3000/docs`
- Health check: `http://localhost:3000/health`

## Run the Frontend

From the repository root:

```bash
cd frontend
npm install
npm run dev
```

Then open `http://localhost:5173` in your browser. The Vite development server proxies `/api` requests to the FastAPI service on port `3000`.

Connected authentication requires PostgreSQL and FastAPI to be running. The complete startup task described above starts the database, applies migrations, seeds the initial Admin, and launches both application servers.

On Windows PowerShell, use the `.cmd` executable if script execution policy blocks `npm.ps1`:

```powershell
Set-Location frontend
npm.cmd install
npm.cmd run dev
```

Useful frontend checks:

```bash
npm test
npm run build
npm run preview
```

Copy `frontend/.env.example` to `frontend/.env.local` when local API settings need to be customized. Never store secrets in a `VITE_*` variable because Vite exposes those values to the browser bundle.

## Backend API

### `POST /upload`

Uploads and parses a log file.

Request:

- Content type: `multipart/form-data`
- Field name: `logfile`
- Accepted extensions: `.log`, `.csv`, `.txt`, `.json`, `.jsonl`
- Max size: 50 MB

Every route is also served under an `/api` prefix (e.g. `POST /api/upload`) for frontend/API routing.

Authentication and RBAC backend handoff details are documented in
[`docs/backend-auth-rbac.md`](docs/backend-auth-rbac.md).

### `GET /upload/formats`

Returns accepted upload formats.

### `GET /health`

Returns backend service health.

### Full endpoint list

| Area | Endpoints |
| --- | --- |
| Auth | `POST /auth/login`, `/auth/2fa/verify`, `/auth/2fa/resend`, `/auth/refresh`, `/auth/logout`, `GET /auth/me` |
| Users | `GET/POST /users`, `PATCH /users/{id}`, role/active/password management |
| Upload | `POST /upload`, `GET /upload/latest`, `/upload/history`, `/upload/batches/{id}`, `/upload/formats` |
| Detection | `GET /detection/rules`, `PATCH /detection/rules/{name}` |
| Custom rules | `GET/POST /custom-rules`, `PATCH/DELETE /custom-rules/{id}`, `POST /custom-rules/test` |
| Alerts / Incidents / Notes | `GET/PATCH /alerts`, `GET/POST/PATCH /incidents`, `GET/POST/PATCH/DELETE /notes` |

Full request/response contracts and RBAC rules are in [`docs/backend-auth-rbac.md`](docs/backend-auth-rbac.md) and the backend test suite (`backend/tests/`).

## Output

The standalone parser script writes `output/parsed_logs_sprint2.json` and `output/parsed_logs_sprint2.csv`.

The backend API returns JSON containing:

- Upload metadata
- Parsing summary
- Parsed entries
- Skipped lines
- Error details when validation fails

## Frontend

The production-oriented frontend is a React, Vite, and Tailwind CSS security-operations workspace based on the CyberShield Figma design. It contains authentication, role-aware navigation, operational dashboards, event and alert investigation, incident workflows, analyst notes, AI-assisted analysis, administration, and backend-ready repository adapters.

### Frontend features

- Responsive light and dark themes with accessible keyboard navigation and reduced-motion support
- Login, MFA, recovery, UTA SSO, support, logout, session-expiration, and protected-route experiences
- Viewer, Analyst, and Admin permissions with unauthorized actions hidden or disabled
- Backend-connected dashboard metrics, interactive time-series and severity charts, telemetry health, security grade, IP statistics, threat analysis, and analyst workload
- Event ingestion for `.log`, `.csv`, `.json`, and `.jsonl`, with validation, filters, search, pagination, exports, and normalized evidence detail
- Alert investigation with severity, source IP, affected user, detection rule, reason, time range, evidence, and recommended response actions
- Incident creation and tracking with Open, Investigating, Resolved, and False Positive states, analyst notes, history, attribution, and quick-resolve workflow
- AI analysis, analyst-note storage and history, integrations, system management, settings, help, notifications, loading, empty, and error states
- Replaceable mock and HTTP repository adapters that keep browser-only demonstration data separate from connected production behavior

### Frontend documentation

- [Frontend architecture](frontend/docs/ARCHITECTURE.md)
- [Frontend/backend contract](frontend/docs/BACKEND_CONTRACT.md)
- [Connected local setup](frontend/docs/CONNECTED_BACKEND.md)
- [Deployment and documentation checklist](docs/deployment_and_documentation.md)
- [Workflow validation](frontend/docs/WORKFLOW_VALIDATION.md)
- [Interaction test report](frontend/docs/INTERACTION_TEST_REPORT.md)
- [Security policy and frontend boundary](SECURITY.md)

## Tech Stack

- React.js
- Vite
- Tailwind CSS
- FastAPI (Python)
- Docker
- PostgreSQL
- Alembic

## Folder Structure

- `parser/` - parser source code
- `sample-logs/` - test input logs
- `output/` - generated parsed files
- `docs/` - backend and Sprint documentation
- `backend/` - FastAPI backend upload, authentication, RBAC, alert, incident, note, and user APIs
- `frontend/` - React/Vite/Tailwind SOC application
- `frontend/docs/` - frontend architecture, integration, workflow, and test documentation
- `frontend/tests/` - frontend validation, permissions, workflow, chart, repository, and utility tests

## Team Members

| Name | Role |
| --- | --- |
| Yugal Limbu | Project Manager / Documentation Lead |
| Marvellous Obasanya | Scrum Master |
| Paul Truong | Frontend Developer |
| Samin Rijal | Backend Developer |
| Kapil Khanal | ML / DevOps / Testing Lead |
