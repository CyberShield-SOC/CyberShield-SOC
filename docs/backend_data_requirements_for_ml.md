# Backend Data Requirements for Later ML Integration

## Current Authoritative Sources

- `upload_batches`: one row per uploaded file with filename, format, MIME type, byte size, line counts, parsed-entry counts, skipped-line counts, alert counts, and upload timestamp.
- `logs`: normalized event-level records keyed by `upload_id` and `line_number`, with timestamp, IP address, username, event type, status, severity, raw message, and full parser output in `parsed_data`.
- `alerts`: deterministic rule outputs keyed by `upload_id`, with rule name, severity, status, source IP, username, event count, window, first/last seen timestamps, description, and matched line numbers.
- `incidents` and `notes`: analyst workflow labels, investigation context, status changes, assignments, and free-text notes that can become later supervised-learning labels after review.

## Minimum ML Feature Contract

- Stable event identity: `upload_id` plus `line_number`.
- Event time: `event_timestamp` when parsed, otherwise `ingested_at` as a fallback feature only.
- Actor and source fields: `ip_address`, `username`, `event_type`, `status`, and normalized `severity`.
- Raw evidence: `raw_message` and `parsed_data` retained for feature extraction and parser improvements.
- Batch context: `source_format`, `source_filename`, and upload-level parse quality counts from `upload_batches`.
- Rule context: alert `rule`, `event_count`, `time_window_seconds`, `matched_line_numbers`, and alert lifecycle `status`.
- Human review labels: incident priority/status, false-positive status, assignments, and analyst notes after project policy defines which fields are approved as labels.

## Data Quality Requirements

- Parser changes must preserve the existing canonical field names used by the detection engine: `timestamp`, `ip_address`, `username`, `event_type`, and `status`.
- Uploads must remain append-only by batch; re-uploading the same file creates a new `upload_id`.
- Failed persistence must rollback logs, alerts, and batch metadata together.
- Malformed lines should be counted and retained in upload parse statistics without creating shifted or guessed event rows.
- ML exports should exclude authentication secrets and should treat `raw_message` and `parsed_data` as potentially sensitive security data.
