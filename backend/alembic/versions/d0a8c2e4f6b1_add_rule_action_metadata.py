"""add rule action metadata

Revision ID: d0a8c2e4f6b1
Revises: b4a1f6c9d3e7
Create Date: 2026-09-12 18:15:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "d0a8c2e4f6b1"
down_revision: Union[str, Sequence[str], None] = "b4a1f6c9d3e7"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "alerts",
        sa.Column(
            "response_playbook",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
    )
    op.add_column(
        "alerts",
        sa.Column(
            "action_results",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
    )
    op.add_column(
        "incidents",
        sa.Column(
            "response_playbook",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
    )


def downgrade() -> None:
    op.drop_column("incidents", "response_playbook")
    op.drop_column("alerts", "action_results")
    op.drop_column("alerts", "response_playbook")
