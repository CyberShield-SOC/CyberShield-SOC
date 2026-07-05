# CyberShield SOC

AI-Powered Log Monitoring and Threat Detection Platform.

## Scope

This prototype includes log ingestion, parsing, detection-rule processing, and a React dashboard for `.log` and `.csv` security logs.

## Included

- Backend FastAPI upload API
- File validation for `.log` and `.csv`
- Parser handoff and parsed JSON responses
- Detection engine with brute-force login, invalid-user, and sudo-failure rules
- Upload response alerts
- Dashboard alerts API
- React/Vite/Tailwind frontend
- Sample security logs and backend tests

## Run the Backend API

Install backend dependencies:

```bash
pip install -r backend/requirements.txt
```

Run the server:

```bash
cd backend
python main.py
```

Open:

- Frontend dashboard: `http://localhost:5173` with Vite dev server running
- API docs: `http://localhost:3000/docs`
- Health check: `http://localhost:3000/health`

## Run the Frontend

```bash
cd frontend
npm install
npm run dev
```

Then open `http://localhost:5173`.

## Backend API

### `POST /upload`

Uploads, validates, parses, and analyzes a log file.

- Content type: `multipart/form-data`
- Field name: `logfile`
- Accepted extensions: `.log`, `.csv`
- Max size: 10 MB

The project also supports `POST /api/upload`.

The response contains upload metadata, parsing summary, parsed entries, skipped lines, detection summary, and generated alerts.

### `GET /alerts`

Returns the latest generated alerts for the dashboard.

The project also supports `GET /api/alerts`.

### `GET /upload/formats`

Returns accepted upload formats.

### `GET /health`

Returns backend service health.

## Run Tests

```bash
cd backend
pytest
```

## Folder Structure

- `backend/` - FastAPI backend upload, parser integration, and detection API
- `frontend/` - React/Vite/Tailwind dashboard
- `parser/` - standalone parser source
- `sample-logs/` - test input logs
- `output/` - generated parsed files
- `docs/` - project documentation
