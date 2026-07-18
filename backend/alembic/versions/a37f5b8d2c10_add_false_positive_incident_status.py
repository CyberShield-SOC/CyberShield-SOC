"""add false-positive incident status

Revision ID: a37f5b8d2c10
Revises: d82a91f640c3
Create Date: 2026-07-17 00:00:00.000000
"""

from typing import Sequence, Union

from alembic import op


revision: str = "a37f5b8d2c10"
down_revision: Union[str, Sequence[str], None] = "d82a91f640c3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_constraint(
        "ck_incidents_status",
        "incidents",
        type_="check",
    )
    # CLOSED was the previous terminal state. Preserve those completed
    # investigations as RESOLVED before narrowing the supported workflow.
    op.execute(
        """
        UPDATE incidents
        SET status = 'RESOLVED',
            resolved_at = COALESCE(resolved_at, closed_at, updated_at)
        WHERE status = 'CLOSED'
        """
    )
    op.create_check_constraint(
        "ck_incidents_status",
        "incidents",
        "status IN ('OPEN', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE')",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_incidents_status",
        "incidents",
        type_="check",
    )
    op.execute(
        """
        UPDATE incidents
        SET status = 'CLOSED'
        WHERE status = 'FALSE_POSITIVE'
        """
    )
    op.create_check_constraint(
        "ck_incidents_status",
        "incidents",
        "status IN ('OPEN', 'INVESTIGATING', 'RESOLVED', 'CLOSED')",
    )
