import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.main import app
from app.models.role import Role
from app.models.user import User
from app.security import current_user

client = TestClient(app)


def fake_user(role_name: str = "Admin") -> User:
    user = User(
        id=1,
        role_id=1,
        username=f"{role_name.lower()}1",
        email=f"{role_name.lower()}1@example.test",
        password_hash="not-returned",
        is_active=True,
    )
    user.role = Role(id=1, name=role_name)
    return user


@pytest.fixture(autouse=True)
def authenticated_admin():
    app.dependency_overrides[current_user] = lambda: fake_user("Admin")
    yield
    app.dependency_overrides.pop(current_user, None)


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "timestamp" in data


def test_api_health_alias():
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_upload_formats_requires_authentication():
    app.dependency_overrides.pop(current_user, None)
    response = client.get("/upload/formats")
    assert response.status_code == 401


def test_upload_formats():
    response = client.get("/upload/formats")
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    extensions = [f["extension"] for f in data["accepted_formats"]]
    assert ".log" in extensions
    assert ".csv" in extensions
    assert ".json" in extensions
    assert ".jsonl" in extensions


def test_upload_history_lists_every_persisted_batch():
    from io import BytesIO

    first = client.post(
        "/upload",
        files={
            "logfile": (
                "first.csv",
                BytesIO(b"timestamp,ip_address,username,event_type,status\n2026-07-17T10:00:00Z,203.0.113.1,analyst,login,FAILED\n"),
                "text/csv",
            )
        },
    )
    second = client.post(
        "/upload",
        files={
            "logfile": (
                "second.jsonl",
                BytesIO(b'{"timestamp":"2026-07-17T10:01:00Z","src_ip":"198.51.100.2","event":"dns_query","status":"success"}\n'),
                "application/x-ndjson",
            )
        },
    )
    assert first.status_code == 200
    assert second.status_code == 200

    response = client.get("/upload/history?page=1&page_size=25")
    assert response.status_code == 200
    payload = response.json()
    uploads = {upload["filename"]: upload for upload in payload["uploads"]}
    assert {"first.csv", "second.jsonl"}.issubset(uploads)
    assert uploads["first.csv"]["stored_entries"] == 1
    assert uploads["second.jsonl"]["format"] == "json"
    assert payload["pagination"]["total"] >= 2

    search_response = client.get("/upload/history?query=first.csv")
    assert search_response.status_code == 200
    search_payload = search_response.json()
    assert search_payload["pagination"]["total"] == 1
    assert [upload["filename"] for upload in search_payload["uploads"]] == ["first.csv"]

    first_upload_id = first.json()["upload"]["upload_id"]
    batch_response = client.get(f"/upload/batches/{first_upload_id}")
    assert batch_response.status_code == 200
    batch = batch_response.json()
    assert batch["upload"]["filename"] == "first.csv"
    assert batch["upload"]["stored_entries"] == 1
    assert len(batch["logs"]) == 1
    assert all(log["upload_id"] == first_upload_id for log in batch["logs"])


def test_upload_batch_returns_not_found_for_unknown_uuid():
    response = client.get("/upload/batches/00000000-0000-4000-8000-000000000001")
    assert response.status_code == 404


def test_upload_history_requires_authentication():
    app.dependency_overrides.pop(current_user, None)
    response = client.get("/upload/history")
    assert response.status_code == 401

    batch_response = client.get("/upload/batches/00000000-0000-4000-8000-000000000001")
    assert batch_response.status_code == 401


def test_upload_rejects_wrong_extension():
    from io import BytesIO
    response = client.post(
        "/upload",
        files={"logfile": ("test.exe", BytesIO(b"data"), "application/octet-stream")},
    )
    assert response.status_code == 415


def test_upload_rejects_empty_file():
    from io import BytesIO
    response = client.post(
        "/upload",
        files={"logfile": ("test.log", BytesIO(b"   "), "text/plain")},
    )
    assert response.status_code == 400


def test_upload_rejects_binary_content_even_with_log_extension():
    from io import BytesIO
    response = client.post(
        "/upload",
        files={"logfile": ("events.log", BytesIO(b"valid-prefix\x00binary"), "application/octet-stream")},
    )
    assert response.status_code == 415
    assert response.json()["detail"]["code"] == "BINARY_FILE"


def test_upload_rejects_content_above_the_ten_megabyte_limit():
    from io import BytesIO

    from app.middleware.file_validation import MAX_FILE_SIZE_BYTES

    response = client.post(
        "/upload",
        files={
            "logfile": (
                "oversized.log",
                BytesIO(b"a" * (MAX_FILE_SIZE_BYTES + 1)),
                "text/plain",
            )
        },
    )

    assert response.status_code == 413
    assert response.json()["detail"]["code"] == "FILE_TOO_LARGE"


def test_upload_accepts_common_csv_mime_type():
    from io import BytesIO
    csv_content = b"timestamp,ip_address,username,event_type,status\n2024-01-01T00:00:00Z,1.2.3.4,admin,login_attempt,FAILED\n"
    response = client.post(
        "/upload",
        files={"logfile": ("events.csv", BytesIO(csv_content), "application/vnd.ms-excel")},
    )
    assert response.status_code == 200


def test_upload_csv():
    from io import BytesIO
    csv_content = b"timestamp,ip_address,username,event_type,status\n2024-01-01T00:00:00Z,1.2.3.4,admin,login_attempt,FAILED\n"
    response = client.post(
        "/upload",
        files={"logfile": ("events.csv", BytesIO(csv_content), "text/csv")},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert len(data["entries"]) == 1


def test_upload_json_array():
    from io import BytesIO

    content = b'[{"@timestamp":"2026-07-17T12:00:00Z","source":{"ip":"203.0.113.8"},"user":{"name":"analyst"},"event":{"action":"login","outcome":"failure"},"log":{"level":"high"}}]'
    response = client.post(
        "/upload",
        files={"logfile": ("events.json", BytesIO(content), "application/json")},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["parsing"]["format"] == "json"
    assert data["parsing"]["stored_entries"] == 1
    assert data["entries"][0]["parsed"]["ip_address"] == "203.0.113.8"
    assert data["entries"][0]["parsed"]["username"] == "analyst"


def test_upload_jsonl_and_reject_unparseable_json():
    from io import BytesIO

    valid = b'{"timestamp":"2026-07-17T12:00:00Z","src_ip":"198.51.100.4","event":"dns_query","status":"success"}\n'
    valid_response = client.post(
        "/upload",
        files={"logfile": ("events.jsonl", BytesIO(valid), "application/x-ndjson")},
    )
    invalid_response = client.post(
        "/upload",
        files={"logfile": ("broken.json", BytesIO(b"{not-json}"), "application/json")},
    )

    assert valid_response.status_code == 200
    assert valid_response.json()["parsing"]["stored_entries"] == 1
    assert invalid_response.status_code == 422
    assert invalid_response.json()["detail"]["code"] == "NO_PARSEABLE_EVENTS"


def test_upload_syslog():
    from io import BytesIO
    log_content = b"Jun 14 02:11:43 server01 sshd[1234]: Failed password for root from 203.0.113.4 port 22 ssh2\n"
    response = client.post(
        "/upload",
        files={"logfile": ("auth.log", BytesIO(log_content), "text/plain")},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["parsing"]["format"] == "syslog"


def test_upload_brute_force_alert_shape_and_alerts_endpoint():
    from io import BytesIO
    log_content = (
        b"Jun 14 02:11:43 server01 sshd[1]: Failed password for root from 203.0.113.4 port 22 ssh2\n"
        b"Jun 14 02:11:45 server01 sshd[1]: Failed password for root from 203.0.113.4 port 22 ssh2\n"
        b"Jun 14 02:11:47 server01 sshd[1]: Failed password for root from 203.0.113.4 port 22 ssh2\n"
        b"Jun 14 02:11:49 server01 sshd[1]: Failed password for root from 203.0.113.4 port 22 ssh2\n"
        b"Jun 14 02:11:51 server01 sshd[1]: Failed password for root from 203.0.113.4 port 22 ssh2\n"
    )
    response = client.post(
        "/upload",
        files={"logfile": ("auth.log", BytesIO(log_content), "text/plain")},
    )

    assert response.status_code == 200
    alert = response.json()["alerts"][0]
    assert alert["title"] == "Possible brute-force login activity"
    assert alert["severity"] == "HIGH"
    assert alert["ip_address"] == "203.0.113.4"
    assert alert["user"] == "root"
    assert "Brute-force detected" in alert["reason"]
    assert alert["timestamp_range"]["start"]
    assert alert["timestamp_range"]["end"]

    alerts_response = client.get("/alerts")
    assert alerts_response.status_code == 200
    alerts_data = alerts_response.json()
    assert alerts_data["success"] is True
    assert alerts_data["alerts"][0]["rule"] == "brute_force_login"


def test_analyst_can_update_alert_status_and_severity():
    from io import BytesIO

    app.dependency_overrides[current_user] = lambda: fake_user("Analyst")

    log_content = (
        b"Jun 14 02:11:43 server01 sshd[1]: Failed password for root from 203.0.113.4 port 22 ssh2\n"
        b"Jun 14 02:11:45 server01 sshd[1]: Failed password for root from 203.0.113.4 port 22 ssh2\n"
        b"Jun 14 02:11:47 server01 sshd[1]: Failed password for root from 203.0.113.4 port 22 ssh2\n"
        b"Jun 14 02:11:49 server01 sshd[1]: Failed password for root from 203.0.113.4 port 22 ssh2\n"
        b"Jun 14 02:11:51 server01 sshd[1]: Failed password for root from 203.0.113.4 port 22 ssh2\n"
    )
    upload_response = client.post(
        "/upload",
        files={"logfile": ("auth.log", BytesIO(log_content), "text/plain")},
    )
    assert upload_response.status_code == 200
    alert_id = upload_response.json()["alerts"][0]["id"]

    response = client.patch(
        f"/alerts/{alert_id}",
        json={
            "status": "REVIEWING",
            "severity": "CRITICAL",
        },
    )

    assert response.status_code == 200
    alert = response.json()["alert"]
    assert alert["status"] == "REVIEWING"
    assert alert["severity"] == "CRITICAL"


@pytest.mark.parametrize("path", ["/alerts/1", "/incidents/1", "/notes/1"])
def test_patch_rejects_empty_payload(path):
    response = client.patch(path, json={})
    assert response.status_code == 422


def test_list_filters_reject_unknown_enum_values():
    assert client.get("/alerts?severity=URGENT").status_code == 422
    assert client.get("/alerts?status=DISMISSED").status_code == 422
    assert client.get("/incidents?status=WAITING").status_code == 422
    assert client.get("/incidents?priority=URGENT").status_code == 422


def test_complete_persisted_investigation_workflow():
    """Exercise the API chain used by upload, alerts, incidents, and notes UI."""

    from io import BytesIO

    log_content = b"".join(
        f"Jul 17 12:00:0{index} host sshd[1]: Failed password for analyst from 198.51.100.77 port 22 ssh2\n".encode()
        for index in range(1, 6)
    )
    upload = client.post(
        "/upload",
        files={"logfile": ("workflow-auth.log", BytesIO(log_content), "text/plain")},
    )
    assert upload.status_code == 200
    alert_id = upload.json()["alerts"][0]["id"]

    alert_update = client.patch(f"/alerts/{alert_id}", json={"status": "REVIEWING"})
    assert alert_update.status_code == 200

    created = client.post(
        "/incidents",
        json={
            "alert_id": alert_id,
            "title": "Investigate repeated authentication failures",
            "description": "Validate the source and affected identity before containment.",
            "priority": "HIGH",
        },
    )
    assert created.status_code == 201
    incident_id = created.json()["incident"]["id"]

    duplicate = client.post("/incidents", json={"alert_id": alert_id})
    assert duplicate.status_code == 409

    note = client.post(
        f"/incidents/{incident_id}/notes",
        json={
            "title": "Initial investigation",
            "body": "Confirmed repeated failures and preserved the matched authentication evidence.",
            "tags": ["authentication", "triage"],
        },
    )
    assert note.status_code == 201
    note_id = note.json()["note"]["id"]

    edited_note = client.patch(
        f"/notes/{note_id}",
        json={
            "title": "Confirmed authentication investigation",
            "tags": ["authentication", "confirmed"],
            "pinned": True,
            "archived": True,
        },
    )
    incident_notes = client.get(f"/incidents/{incident_id}/notes")

    investigating = client.patch(f"/incidents/{incident_id}", json={"status": "INVESTIGATING"})
    resolved = client.patch(f"/incidents/{incident_id}", json={"status": "RESOLVED"})
    persisted = client.get(f"/incidents/{incident_id}")
    notes = client.get("/notes")

    assert investigating.status_code == 200
    assert edited_note.status_code == 200
    assert edited_note.json()["note"]["pinned"] is True
    assert edited_note.json()["note"]["archived"] is True
    assert incident_notes.json()["notes"][0]["title"] == "Confirmed authentication investigation"
    assert resolved.status_code == 200
    assert persisted.status_code == 200
    assert persisted.json()["incident"]["status"] == "RESOLVED"
    assert any(item["incident_id"] == incident_id for item in notes.json()["notes"])


def test_note_limit_delete_reuse_and_false_positive_completion():
    """Exercise note-cap recovery and the second terminal incident outcome."""

    from io import BytesIO

    log_content = b"".join(
        f"Jul 17 13:00:0{index} host sshd[1]: Failed password for reviewer from 192.0.2.55 port 22 ssh2\n".encode()
        for index in range(1, 6)
    )
    upload = client.post(
        "/upload",
        files={"logfile": ("note-limit-auth.log", BytesIO(log_content), "text/plain")},
    )
    alert_id = upload.json()["alerts"][0]["id"]
    created = client.post(
        "/incidents",
        json={"alert_id": alert_id, "title": "Review note capacity"},
    )
    incident_id = created.json()["incident"]["id"]

    created_notes = [
        client.post(
            f"/incidents/{incident_id}/notes",
            json={"title": f"Step {index}", "body": f"Recorded investigation step {index}."},
        )
        for index in range(1, 6)
    ]
    sixth = client.post(
        f"/incidents/{incident_id}/notes",
        json={"title": "Step 6", "body": "This note must be rejected at the limit."},
    )
    deleted = client.delete(f"/notes/{created_notes[0].json()['note']['id']}")
    replacement = client.post(
        f"/incidents/{incident_id}/notes",
        json={"title": "Replacement", "body": "A deleted slot can be reused safely."},
    )
    completed = client.patch(
        f"/incidents/{incident_id}",
        json={"status": "FALSE_POSITIVE"},
    )

    assert all(response.status_code == 201 for response in created_notes)
    assert sixth.status_code == 409
    assert deleted.status_code == 200
    assert replacement.status_code == 201
    assert completed.status_code == 200
    incident = completed.json()["incident"]
    assert incident["status"] == "FALSE_POSITIVE"
    assert incident["closed_at"] is not None
    assert incident["updated_by_user_id"] == 1
