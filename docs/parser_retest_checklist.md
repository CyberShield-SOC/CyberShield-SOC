# Parser Retest Checklist

Use this checklist after parser, upload, or detection changes.

## Environment

- Backend dependencies are installed.
- Backend starts without import errors.
- API docs load at `http://127.0.0.1:3000/docs`.
- Health check returns `status: ok` from `/health`.

## File Validation Tests

- Upload `.log` file and confirm HTTP `200`.
- Upload `.csv` file and confirm HTTP `200`.
- Upload unsupported file such as `.txt` and confirm HTTP `415`.
- Upload empty `.log` file and confirm validation error.
- Upload non-UTF-8 file and confirm encoding error.

## Parser Tests

- `.csv` file returns parser format `csv`.
- `.log` syslog sample returns parser format `syslog`.
- Apache-style log sample returns parser format `apache_combined`.
- Generic log sample returns parser format `generic`.
- Parsed entries include normalized fields:
  - `timestamp`
  - `ip_address`
  - `username`
  - `event_type`
  - `status`
- Invalid or unmatched lines are listed in `skipped_lines`.

## Detection Tests

- Upload a brute-force `.log` sample with 5 failed logins from one IP inside the rule window.
- Confirm the upload response includes at least one alert.
- Confirm the alert rule is `brute_force_login`.
- Confirm alert fields include title, severity, IP address, user, reason, and timestamp range.
- Upload a clean log sample and confirm no brute-force alert is generated.

## Alerts API Tests

- After uploading a suspicious log, call `GET /alerts`.
- Confirm the response includes `success`, `total_alerts`, and `alerts`.
- Confirm `GET /api/alerts` returns the same structure.

## Commands Used

```bash
cd backend
python -m compileall app
```

If test dependencies are installed:

```bash
cd backend
python -m pytest
```

## Latest Manual Retest Result

- Backend syntax compilation passed.
- `.log` upload smoke test returned parsed entries and a brute-force alert.
- `.csv` upload smoke test returned parsed entries and a brute-force alert.
- Unsupported `.txt` upload returned `415 INVALID_FILE_TYPE`.
