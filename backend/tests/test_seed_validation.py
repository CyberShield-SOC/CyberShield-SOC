from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.db.seed import DEFAULT_ROLES, SEED_ACCOUNT_ENV

pytestmark = pytest.mark.no_db


def test_seed_definitions_cover_admin_analyst_and_viewer():
    role_names = {role["name"] for role in DEFAULT_ROLES}

    assert {"Admin", "Analyst", "Viewer"} <= role_names
    assert set(SEED_ACCOUNT_ENV) == {"Admin", "Analyst", "Viewer"}
    for config in SEED_ACCOUNT_ENV.values():
        assert config["username"][0].startswith("CYBERSHIELD_")
        assert config["email"][0].startswith("CYBERSHIELD_")
        assert config["password"].startswith("CYBERSHIELD_")
