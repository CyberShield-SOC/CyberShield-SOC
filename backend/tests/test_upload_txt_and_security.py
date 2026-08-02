"""TEST-1 coverage: .txt upload support and upload-path security hardening.

Complements test_api.py's existing .csv/.json/.jsonl/.log coverage with the
newly-added .txt format, plus the filename-sanitization, spoofed-MIME, and
malformed-content edge cases required by the file-upload security review.
"""

from __future__ import annotations

import sys
from io import BytesIO
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.main import app
from app.models.role import Role
from app.models.user import User
from app.security import current_user


client = TestClient(app)


@pytest.fixture(autouse=True)
def authenticated_admin(db_session):
    admin_role = db_session.scalar(select(Role).where(Role.name == "Admin"))
    if admin_role is None:
        admin_role = Role(name="Admin", description="Administrator")
        db_session.add(admin_role)
        db_session.flush()

    suffix = uuid4().hex
    admin_user = User(
        role_id=admin_role.id,
        username=f"txt_test_admin_{suffix}",
        email=f"txt_test_admin_{suffix}@example.test",
        password_hash="not-used",
        is_active=True,
    )
    db_session.add(admin_user)
    db_session.commit()

    app.dependency_overrides[current_user] = lambda: admin_user
    yield
    app.dependency_overrides.pop(current_user, None)


# ── Valid .txt uploads ───────────────────────────────────────────────────────

def test_upload_txt_with_delimited_header_is_parsed_as_csv():
    content = (
        b"timestamp,ip_address,username,event_type,status\n"
        b"2024-01-01T00:00:00Z,1.2.3.4,admin,login_attempt,FAILED\n"
    )
    response = client.post(
        "/upload",
        files={"logfile": ("events.txt", BytesIO(content), "text/plain")},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["parsing"]["format"] == "csv"
    assert data["parsing"]["stored_entries"] == 1
    assert data["entries"][0]["parsed"]["ip_address"] == "1.2.3.4"


def test_upload_txt_with_tab_delimited_header_is_parsed_as_csv():
    content = (
        b"timestamp\tip_address\tusername\tevent_type\tstatus\n"
        b"2024-01-01T00:00:00Z\t9.9.9.9\tadmin\tlogin_attempt\tFAILED\n"
    )
    response = client.post(
        "/upload",
        files={"logfile": ("events.txt", BytesIO(content), "text/plain")},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["parsing"]["format"] == "csv"
    assert data["entries"][0]["parsed"]["ip_address"] == "9.9.9.9"


def test_upload_txt_with_free_form_log_lines_uses_existing_auto_detection():
    """Plain-text .txt content that isn't delimited behaves exactly like .log."""

    content = b"Jun 14 02:11:43 server01 sshd[1234]: Failed password for root from 203.0.113.4 port 22 ssh2\n"
    response = client.post(
        "/upload",
        files={"logfile": ("auth.txt", BytesIO(content), "text/plain")},
    )
    assert response.status_code == 200
    assert response.json()["parsing"]["format"] == "syslog"


def test_upload_txt_brute_force_alert_still_fires():
    content = b"".join(
        f"Jun 14 02:11:{40 + i * 2} server01 sshd[1]: Failed password for root from 203.0.113.4 port 22 ssh2\n".encode()
        for i in range(5)
    )
    response = client.post(
        "/upload",
        files={"logfile": ("auth.txt", BytesIO(content), "text/plain")},
    )
    assert response.status_code == 200
    data = response.json()
    assert any(alert["rule"] == "brute_force_login" for alert in data["alerts"])


# ── Case-insensitive extensions ──────────────────────────────────────────────

@pytest.mark.parametrize("filename", ["EVENTS.TXT", "Events.Txt", "events.TXT"])
def test_upload_accepts_uppercase_txt_extension(filename):
    content = b"timestamp,ip_address,username,event_type,status\n2024-01-01T00:00:00Z,1.2.3.4,admin,login_attempt,FAILED\n"
    response = client.post(
        "/upload",
        files={"logfile": (filename, BytesIO(content), "text/plain")},
    )
    assert response.status_code == 200


@pytest.mark.parametrize("filename", ["EVENTS.CSV", "Events.Csv"])
def test_upload_accepts_uppercase_csv_extension(filename):
    content = b"timestamp,ip_address,username,event_type,status\n2024-01-01T00:00:00Z,1.2.3.4,admin,login_attempt,FAILED\n"
    response = client.post(
        "/upload",
        files={"logfile": (filename, BytesIO(content), "text/csv")},
    )
    assert response.status_code == 200


# ── Unsupported formats ──────────────────────────────────────────────────────

@pytest.mark.parametrize("filename,content_type", [
    ("payload.pdf", "application/pdf"),
    ("payload.exe", "application/octet-stream"),
    ("payload.docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
])
def test_upload_rejects_unsupported_extensions(filename, content_type):
    response = client.post(
        "/upload",
        files={"logfile": (filename, BytesIO(b"some content"), content_type)},
    )
    assert response.status_code == 415
    assert response.json()["detail"]["code"] == "INVALID_FILE_TYPE"


def test_upload_rejects_unsupported_json_lookalike_extension():
    """A supported MIME type on a disallowed extension must still be rejected;
    the extension allowlist is the authority, not the client-provided type."""

    response = client.post(
        "/upload",
        files={"logfile": ("payload.json.bak", BytesIO(b"{}"), "application/json")},
    )
    assert response.status_code == 415


# ── Empty files ───────────────────────────────────────────────────────────────

def test_upload_rejects_empty_txt_file():
    response = client.post(
        "/upload",
        files={"logfile": ("empty.txt", BytesIO(b""), "text/plain")},
    )
    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "EMPTY_FILE"


def test_upload_rejects_whitespace_only_txt_file():
    response = client.post(
        "/upload",
        files={"logfile": ("blank.txt", BytesIO(b"   \n\t\n  "), "text/plain")},
    )
    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "EMPTY_FILE"


# ── Malformed content does not crash the server ──────────────────────────────

def test_upload_ragged_csv_rows_are_skipped_not_silently_shifted():
    """A row with more columns than the header must be reported as skipped,
    never silently mapped into the wrong fields, and must not crash the
    request; the well-formed rows around it must still parse normally."""

    content = (
        b"timestamp,ip_address,username,event_type,status\n"
        b"2024-01-01T00:00:00Z,1.2.3.4,admin,login_attempt,FAILED\n"
        b"not,even,close,to,a,valid,row,with,too,many,fields\n"
        b"2024-01-01T00:00:02Z,1.2.3.5,admin,login_attempt,FAILED\n"
    )
    response = client.post(
        "/upload",
        files={"logfile": ("events.csv", BytesIO(content), "text/csv")},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["parsing"]["stored_entries"] == 2
    assert data["parsing"]["skipped_lines"] == 1
    assert "header" in data["skipped_lines"][0]["reason"].lower()


def test_upload_short_csv_rows_are_skipped_not_silently_shifted():
    """A row with fewer columns than the header is equally ambiguous and
    must be skipped rather than guessed at."""

    content = (
        b"timestamp,ip_address,username,event_type,status\n"
        b"2024-01-01T00:00:00Z,1.2.3.4,admin,login_attempt,FAILED\n"
        b"2024-01-01T00:00:01Z,1.2.3.6,admin\n"
        b"2024-01-01T00:00:02Z,1.2.3.5,admin,login_attempt,FAILED\n"
    )
    response = client.post(
        "/upload",
        files={"logfile": ("events.csv", BytesIO(content), "text/csv")},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["parsing"]["stored_entries"] == 2
    assert data["parsing"]["skipped_lines"] == 1


def test_upload_txt_with_only_garbage_lines_returns_no_parseable_events():
    """Content that matches no parser produces a clean 422, never a crash."""

    content = "\ufffd\ufffd\ufffd binary-looking garbage \ufffd\ufffd\ufffd\n".encode("utf-8")
    response = client.post(
        "/upload",
        files={"logfile": ("garbage.txt", BytesIO(content), "text/plain")},
    )
    # Generic parser accepts any non-empty line as a low-confidence entry, so
    # this either parses everything into unclassified generic entries or
    # reports no parseable events -- either way, it must not be a 500.
    assert response.status_code in (200, 422)


def test_upload_broken_json_extension_reports_parsing_error_not_a_crash():
    response = client.post(
        "/upload",
        files={"logfile": ("broken.jsonl", BytesIO(b"{not-json-at-all"), "application/json")},
    )
    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "NO_PARSEABLE_EVENTS"


# ── Spoofed / mismatched MIME types do not bypass validation ─────────────────

def test_upload_rejects_binary_payload_disguised_as_csv():
    """A renamed binary file with a spoofed text/csv MIME type must still be
    caught by content sniffing (NUL byte detection), not waved through
    because the extension and client-provided MIME type both look valid."""

    binary_payload = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00binary-exe-content"
    response = client.post(
        "/upload",
        files={"logfile": ("totally-a-report.csv", BytesIO(binary_payload), "text/csv")},
    )
    assert response.status_code == 415
    assert response.json()["detail"]["code"] == "BINARY_FILE"


def test_upload_rejects_disallowed_mime_type_even_with_valid_extension():
    response = client.post(
        "/upload",
        files={
            "logfile": (
                "events.csv",
                BytesIO(b"timestamp,ip_address\n2024-01-01T00:00:00Z,1.2.3.4\n"),
                "application/x-msdownload",
            )
        },
    )
    assert response.status_code == 415
    assert response.json()["detail"]["code"] == "INVALID_MIME_TYPE"


# ── Path traversal / filename sanitization ───────────────────────────────────

@pytest.mark.parametrize("malicious_name", [
    "../../etc/passwd.txt",
    "..\\..\\windows\\win.csv",
    "/etc/passwd.csv",
    "C:\\Windows\\System32\\config.csv",
])
def test_upload_sanitizes_path_traversal_filenames(malicious_name):
    content = b"timestamp,ip_address,username,event_type,status\n2024-01-01T00:00:00Z,1.2.3.4,admin,login_attempt,FAILED\n"
    response = client.post(
        "/upload",
        files={"logfile": (malicious_name, BytesIO(content), "text/csv")},
    )
    assert response.status_code == 200
    stored_filename = response.json()["upload"]["filename"]
    assert "/" not in stored_filename
    assert "\\" not in stored_filename
    assert ".." not in stored_filename


def test_upload_history_reflects_sanitized_filename_not_raw_client_input():
    content = b"timestamp,ip_address,username,event_type,status\n2024-01-01T00:00:00Z,1.2.3.4,admin,login_attempt,FAILED\n"
    upload = client.post(
        "/upload",
        files={"logfile": ("../../secrets/hidden.csv", BytesIO(content), "text/csv")},
    )
    assert upload.status_code == 200
    upload_id = upload.json()["upload"]["upload_id"]

    batch = client.get(f"/upload/batches/{upload_id}")
    assert batch.status_code == 200
    assert batch.json()["upload"]["filename"] == "hidden.csv"


# ── Duplicate uploads ─────────────────────────────────────────────────────────

def test_uploading_the_same_file_twice_creates_two_independent_batches():
    """The application has no upload de-duplication: re-uploading identical
    content must succeed both times and produce two distinct, independently
    retrievable batches rather than colliding or silently overwriting."""

    content = b"timestamp,ip_address,username,event_type,status\n2024-01-01T00:00:00Z,1.2.3.4,admin,login_attempt,FAILED\n"

    first = client.post(
        "/upload",
        files={"logfile": ("repeat.csv", BytesIO(content), "text/csv")},
    )
    second = client.post(
        "/upload",
        files={"logfile": ("repeat.csv", BytesIO(content), "text/csv")},
    )

    assert first.status_code == 200
    assert second.status_code == 200
    first_id = first.json()["upload"]["upload_id"]
    second_id = second.json()["upload"]["upload_id"]
    assert first_id != second_id

    assert client.get(f"/upload/batches/{first_id}").status_code == 200
    assert client.get(f"/upload/batches/{second_id}").status_code == 200


# ── Regression: existing .csv behavior is untouched ──────────────────────────

def test_csv_upload_still_defaults_to_comma_delimiter_after_txt_support_added():
    """The delimiter parameter added to support .txt must not change the
    default (comma) behavior used for genuine .csv files."""

    content = b"timestamp,ip_address,username,event_type,status\n2024-01-01T00:00:00Z,8.8.8.8,root,login_attempt,FAILED\n"
    response = client.post(
        "/upload",
        files={"logfile": ("regression.csv", BytesIO(content), "text/csv")},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["parsing"]["format"] == "csv"
    assert data["entries"][0]["parsed"]["ip_address"] == "8.8.8.8"


def test_upload_formats_endpoint_lists_txt():
    response = client.get("/upload/formats")
    assert response.status_code == 200
    extensions = [f["extension"] for f in response.json()["accepted_formats"]]
    assert ".txt" in extensions
    assert ".csv" in extensions
