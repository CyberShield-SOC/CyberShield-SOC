import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.main import app

client = TestClient(app)


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "timestamp" in data


def test_upload_formats():
    response = client.get("/upload/formats")
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    extensions = [f["extension"] for f in data["accepted_formats"]]
    assert ".log" in extensions
    assert ".csv" in extensions


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
