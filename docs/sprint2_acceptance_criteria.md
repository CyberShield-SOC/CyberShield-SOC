# Sprint 2 Acceptance Criteria

## Upload API

- The backend exposes `POST /upload`.
- The backend also supports `POST /api/upload`.
- The request accepts multipart form data with field name `logfile`.
- The upload endpoint reads the uploaded file content before parser execution.

## File Validation

- Only `.log` and `.csv` files are accepted.
- Unsupported extensions return an error response before parsing.
- Empty files return a validation error.
- Files larger than the configured size limit return a validation error.
- Files that cannot be decoded as UTF-8 return an encoding error.

## Parser Integration

- `.csv` files are routed to the CSV parser.
- `.log` files are routed through automatic parser detection.
- Parsed entries include normalized fields:
  - `timestamp`
  - `ip_address`
  - `username`
  - `event_type`
  - `status`
- Skipped or unparseable lines are returned separately.

## Detection Rules

- Parsed entries are converted into detection records.
- The detection engine runs registered backend rules.
- Brute-force login detection triggers when failed login attempts meet the configured threshold and time window.
- Detection output is returned in the upload response.

## Alert Response

- Alerts include:
  - `title`
  - `severity`
  - `ip_address`
  - `user`
  - `reason`
  - `timestamp_range`
- The upload response includes an `alerts` array.
- The upload response includes detection metadata with rules run and alert count.
- The dashboard can retrieve latest alerts through `GET /alerts` or `GET /api/alerts`.

## Testing Criteria

- A valid `.log` sample returns HTTP `200`, parsed entries, and detection output.
- A valid `.csv` sample returns HTTP `200`, parsed entries, and detection output.
- A brute-force sample generates at least one brute-force alert.
- An unsupported file type returns HTTP `415`.
- Backend syntax compilation passes.
