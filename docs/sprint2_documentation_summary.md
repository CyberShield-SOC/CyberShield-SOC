# Sprint 2 Documentation Summary

## Sprint 2 Focus

Sprint 2 focuses on connecting backend log ingestion to detection rule processing and returning useful JSON responses for the dashboard.

## Completed Backend Work

- Improved `/upload` endpoint for file upload.
- Validated uploaded file type before parsing.
- Restricted accepted files to `.log` and `.csv`.
- Returned clear JSON errors for unsupported files.
- Connected uploaded log content to the parser workflow.
- Returned parsed log results as JSON.
- Added detection engine structure for parsed logs.
- Implemented brute-force login detection.
- Generated dashboard-ready alert objects.
- Added alerts API endpoint for dashboard retrieval.
- Retested backend behavior with sample `.log`, `.csv`, and invalid file uploads.

## Important Backend Files

- `backend/app/routers/upload.py`
- `backend/app/routers/alerts.py`
- `backend/app/middleware/file_validation.py`
- `backend/app/parsers/log_parser.py`
- `backend/app/parsers/csv_parser.py`
- `backend/app/parsers/field_normalizer.py`
- `backend/app/detection/engine.py`
- `backend/app/detection/models.py`
- `backend/app/detection/rules/brute_force.py`
- `backend/app/detection/alert_store.py`

## API Summary

### Upload

`POST /upload`

Also available as:

`POST /api/upload`

Returns:

- Upload metadata
- Parsing summary
- Parsed entries
- Skipped lines
- Detection summary
- Generated alerts

### Alerts

`GET /alerts`

Also available as:

`GET /api/alerts`

Returns:

- `success`
- `total_alerts`
- `alerts`

## Known Limitations

- Alert storage is currently in-memory.
- Full automated test execution requires test dependencies such as `pytest`.
- Detection rules currently depend on normalized parser fields being accurate.

## Next Steps

- Add persistent database storage for alerts.
- Add authentication or role-based access for dashboard APIs.
- Expand detection coverage with more SOC rules.
- Add CI test execution for parser and detection workflows.
