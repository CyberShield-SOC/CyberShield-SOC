import pytest
from pydantic import ValidationError

from app.models.incident import Incident
from app.schemas.incident import IncidentUpdate


def test_incident_status_contract_includes_false_positive_and_rejects_closed():
    assert IncidentUpdate(status="FALSE_POSITIVE").status == "FALSE_POSITIVE"
    with pytest.raises(ValidationError):
        IncidentUpdate(status="CLOSED")

    status_constraint = next(
        constraint
        for constraint in Incident.__table__.constraints
        if getattr(constraint, "name", None) == "ck_incidents_status"
    )
    assert "FALSE_POSITIVE" in str(status_constraint.sqltext)
    assert "'CLOSED'" not in str(status_constraint.sqltext)
