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

## Run the Parser

```bash
python parser/log_parser.py sample-logs/auth.log
```

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

- Frontend dashboard: `http://localhost:5173` (with Vite dev server running)
- API docs: `http://localhost:3000/docs`
- Health check: `http://localhost:3000/health`

## Run the Frontend

```bash
cd frontend
npm install
npm run dev
```

Then open `http://localhost:5173` in your browser.

## Backend API

### `POST /upload`

Uploads and parses a log file.

Request:

- Content type: `multipart/form-data`
- Field name: `logfile`
- Accepted extensions: `.log`, `.csv`
- Max size: 10 MB

The project also supports `POST /api/upload` for frontend/API routing.

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

React/Vite/Tailwind dashboard for uploading and viewing parsed security logs.

## Features

- Drag-and-drop file upload
- Select file button
- Supports `.log` and `.csv`
- Parsed logs table
- Log search/filter
- Parsed log count
- Threat analysis cards
- Responsive layout

## Tech Stack

- React.js
- Vite
- Tailwind CSS
- FastAPI (Python)
- Docker
- PosgreSQL
- Alembic

## Folder Structure

- `parser/` - parser source code
- `sample-logs/` - test input logs
- `output/` - generated parsed files
- `docs/` - Sprint 1 documentation
- `backend/` - FastAPI backend upload API
- `frontend/` - React/Vite/Tailwind dashboard

## Team Members

| Name | Role |
|------|------|
| Yugal Limbu | Project Manager / Documentation Lead |
| Paul Truong | Frontend Developer |
| Samin Rijal | Backend Developer |
| Marvellous Obasanya | Cybersecurity / Detection Lead |
| Kapil Khanal | ML / DevOps / Testing Lead |
