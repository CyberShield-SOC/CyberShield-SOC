# CyberShield SOC

AI-Powered Log Monitoring and Threat Detection Platform

## Sprint 1 Scope

This Sprint 1 prototype focuses on log ingestion and parsing. It includes a parser workflow for raw authentication/security logs and a FastAPI backend for uploading `.log` or `.csv` files, validating them, parsing basic fields, and returning structured JSON.

## Sprint 1 Deliverables Included

- Python parser script (`parser/log_parser.py`)
- Sample security log dataset (`sample-logs/auth.log`)
- Parsed JSON output (`output/parsed_logs.json`)
- Parsed CSV output (`output/parsed_logs.csv`)
- Backend FastAPI upload API (`backend/`)
- File validation for `.log` and `.csv`
- JSON response with parsed log entries
- Setup documentation
- Parser design documentation
- GitHub submission guide
- Kapil Khanal contribution report
- Sprint 1 deliverables summary

## One-time local setup

Install these prerequisites before continuing:

- Docker Desktop with the Docker engine running
- Python 3.13
- Node.js 24 and npm

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
.\.venv\Scripts\python.exe -m pytest tests -q -p no:cacheprovider
```

## Run the Parser

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
- Accepted extensions: `.log`, `.csv`
- Max size: 10 MB

The project also supports `POST /api/upload` for frontend/API routing.

Authentication and RBAC backend handoff details are documented in
[`docs/backend-auth-rbac.md`](docs/backend-auth-rbac.md).

### `GET /upload/formats`

Returns accepted upload formats.

### `GET /health`

Returns backend service health.

## Backend Coverage

| Sprint 1 requirement | Included |
|---|---|
| Backend project setup | Yes |
| `POST /upload` endpoint | Yes |
| `.log` and `.csv` file validation | Yes |
| Uploaded file reading | Yes |
| Parser handoff | Yes |
| Parsed JSON response | Yes |
| Error handling for unsupported, empty, large, or bad files | Yes |
| Basic fields: timestamp, IP address, username, event type, status | Yes |
| Simple table display | Yes, React dashboard at `http://localhost:5173` |

## Output

The parser workflow generates:

- `output/parsed_logs.json`
- `output/parsed_logs.csv`

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
- [Workflow validation](frontend/docs/WORKFLOW_VALIDATION.md)
- [Interaction test report](frontend/docs/INTERACTION_TEST_REPORT.md)
- [Frontend security boundary](frontend/docs/SECURITY.md)

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
|------|------|
| Yugal Limbu | Project Manager / Documentation Lead |
| Paul Truong | Frontend Developer |
| Samin Rijal | Backend Developer |
| Marvellous Obasanya | Cybersecurity / Detection Lead |
| Kapil Khanal | ML / DevOps / Testing Lead |
