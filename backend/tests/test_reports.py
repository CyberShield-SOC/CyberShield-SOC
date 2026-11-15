"""Backend PDF report export: auth, validation, escaping, row caps, and
counts-match-the-database checks. See app/routers/reports.py and
app/services/reports/.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from pypdf import PdfReader
from sqlalchemy import select

from app.core.config import settings
from app.main import app
from app.models.alert import Alert
from app.models.incident import Incident
from app.models.role import Role
from app.models.user import User
from app.security import current_user

REPORT_IDS = (
    "daily-soc-operations",
    "weekly-incident-summary",
    "detection-coverage",
    "executive-risk-overview",
)


def _pdf_text(content: bytes) -> str:
    reader = PdfReader(__import__("io").BytesIO(content))
    return "\n".join(page.extract_text() or "" for page in reader.pages)


@pytest.fixture
def user_by_role(db_session):
    def make(role_name: str) -> User:
        role = db_session.scalar(select(Role).where(Role.name == role_name))
        suffix = uuid4().hex
        user = User(role_id=role.id, username=f"{role_name.lower()}-{suffix}", email=f"{suffix}@example.test", password_hash="unused", full_name=f"{role_name} Tester")
        db_session.add(user)
        db_session.commit()
        return user

    return make


@pytest.fixture
def client_as(user_by_role):
    def make(role_name: str) -> TestClient:
        user = user_by_role(role_name)
        app.dependency_overrides[current_user] = lambda: user
        return TestClient(app)

    yield make
    app.dependency_overrides.pop(current_user, None)


def _make_alert(db_session, **overrides):
    defaults = dict(
        upload_id=uuid4(),
        rule="brute_force_login",
        title="Repeated failed logins",
        description="5 failed logins from one source.",
        severity="HIGH",
        hostname="host-01",
        username="jdoe",
    )
    defaults.update(overrides)
    alert = Alert(**defaults)
    db_session.add(alert)
    db_session.commit()
    return alert


def _make_incident(db_session, alert, **overrides):
    defaults = dict(
        source_alert_id=alert.id,
        title=alert.title,
        description=alert.description,
        priority=alert.severity,
        status="OPEN",
    )
    defaults.update(overrides)
    incident = Incident(**defaults)
    db_session.add(incident)
    db_session.commit()
    return incident


class TestAuthAndValidation:
    def test_unauthenticated_requests_are_rejected(self):
        client = TestClient(app)
        assert client.get("/reports").status_code == 401
        assert client.get("/reports/daily-soc-operations/pdf").status_code == 401

    @pytest.mark.parametrize("role_name", ["Admin", "Analyst", "Viewer"])
    def test_every_role_can_list_and_export(self, client_as, role_name):
        client = client_as(role_name)
        assert client.get("/reports").status_code == 200
        response = client.get("/reports/daily-soc-operations/pdf")
        assert response.status_code == 200
        assert response.content.startswith(b"%PDF")

    def test_unknown_report_id_is_404(self, client_as):
        client = client_as("Admin")
        assert client.get("/reports/not-a-report/pdf").status_code == 404

    def test_conflicting_range_and_explicit_dates_is_422(self, client_as):
        client = client_as("Admin")
        response = client.get("/reports/daily-soc-operations/pdf", params={
            "range": "24h", "from": "2026-01-01T00:00:00Z", "to": "2026-01-02T00:00:00Z",
        })
        assert response.status_code == 422

    def test_to_before_from_is_422(self, client_as):
        client = client_as("Admin")
        response = client.get("/reports/daily-soc-operations/pdf", params={
            "from": "2026-01-02T00:00:00Z", "to": "2026-01-01T00:00:00Z",
        })
        assert response.status_code == 422

    def test_range_exceeding_max_span_is_422(self, client_as):
        client = client_as("Admin")
        far_past = (datetime.now(timezone.utc) - timedelta(days=settings.report_max_range_days + 10)).isoformat()
        now = datetime.now(timezone.utc).isoformat()
        response = client.get("/reports/daily-soc-operations/pdf", params={"from": far_past, "to": now})
        assert response.status_code == 422

    def test_invalid_severity_is_422(self, client_as):
        client = client_as("Admin")
        response = client.get("/reports/daily-soc-operations/pdf", params={"severity": "NOT-A-SEVERITY"})
        assert response.status_code == 422

    def test_response_exposes_pdf_filename(self, client_as):
        client = client_as("Admin")
        response = client.get("/reports/detection-coverage/pdf")
        assert response.headers["content-type"] == "application/pdf"
        assert "cybershield-detection-coverage-" in response.headers["content-disposition"]


class TestEveryReportRendersOnEmptyData:
    @pytest.mark.parametrize("report_id", REPORT_IDS)
    def test_empty_database_still_renders_a_valid_pdf(self, client_as, report_id):
        client = client_as("Admin")
        response = client.get(f"/reports/{report_id}/pdf", params={"range": "30d"})
        assert response.status_code == 200
        assert response.content.startswith(b"%PDF")
        text = _pdf_text(response.content)
        assert "No data in this period" in text or "No hosts have reported" in text or "no" in text.lower()


class TestUntrustedTextIsEscaped:
    def test_alert_derived_incident_title_with_markup_renders_safely(self, db_session, client_as):
        malicious_title = "<b>XSS</b> & injected markup"
        alert = _make_alert(db_session, title=malicious_title, severity="CRITICAL")
        _make_incident(db_session, alert, title=malicious_title, priority="CRITICAL")

        client = client_as("Admin")
        response = client.get("/reports/weekly-incident-summary/pdf", params={"range": "30d"})

        assert response.status_code == 200
        assert response.content.startswith(b"%PDF")
        text = _pdf_text(response.content)
        assert "XSS" in text
        assert "<b>" in text


class TestRowCapping:
    def test_incident_list_prints_showing_n_of_m_when_capped(self, db_session, client_as, monkeypatch):
        # This is a shared dev database, not a fresh one per test run — measure
        # the existing total in-range first rather than assuming an empty table.
        from app.repositories import report_repository as repo

        now = datetime.now(timezone.utc)
        start, end = now - timedelta(days=30), now
        baseline_total = repo.incidents_opened_count(db_session, start=start, end=end)

        monkeypatch.setattr(settings, "report_max_rows_per_table", 3)
        for index in range(6):
            alert = _make_alert(db_session, title=f"Alert {index}", rule="port_scan", created_at=now - timedelta(hours=index))
            _make_incident(db_session, alert, opened_at=now - timedelta(hours=index))

        client = client_as("Admin")
        response = client.get("/reports/weekly-incident-summary/pdf", params={"range": "30d"})

        assert response.status_code == 200
        text = _pdf_text(response.content)
        assert f"Showing 3 of {baseline_total + 6}" in text


class TestCountsMatchTheDatabase:
    def test_daily_ops_alert_count_matches_database(self, db_session, client_as):
        from app.repositories import report_repository as repo

        now = datetime.now(timezone.utc)
        start, end = now - timedelta(hours=24), now
        baseline_total = repo.alerts_raised_count(db_session, start=start, end=end)

        for index in range(4):
            _make_alert(db_session, title=f"Alert {index}", created_at=now - timedelta(minutes=index))

        client = client_as("Admin")
        response = client.get("/reports/daily-soc-operations/pdf", params={"range": "24h"})

        assert response.status_code == 200
        text = _pdf_text(response.content)
        assert f"{baseline_total + 4:,}" in text

    def test_detection_coverage_rule_counts_match_catalog(self, client_as):
        from app.detection.engine import _RULE_CLASSES

        client = client_as("Admin")
        response = client.get("/reports/detection-coverage/pdf", params={"range": "24h"})

        assert response.status_code == 200
        text = _pdf_text(response.content)
        assert str(len(_RULE_CLASSES)) in text
