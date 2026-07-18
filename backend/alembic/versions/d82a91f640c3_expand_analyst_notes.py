"""expand analyst notes

Revision ID: d82a91f640c3
Revises: b4c9d8e7f102
Create Date: 2026-07-16 00:00:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "d82a91f640c3"
down_revision: Union[str, Sequence[str], None] = "b4c9d8e7f102"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "notes",
        sa.Column("title", sa.String(length=100), server_default="Analyst note", nullable=False),
    )
    op.add_column(
        "notes",
        sa.Column(
            "tags",
            postgresql.ARRAY(sa.String(length=40)),
            server_default=sa.text("'{}'::varchar[]"),
            nullable=False,
        ),
    )
    op.add_column(
        "notes",
        sa.Column("pinned", sa.Boolean(), server_default=sa.text("false"), nullable=False),
    )
    op.add_column(
        "notes",
        sa.Column("archived", sa.Boolean(), server_default=sa.text("false"), nullable=False),
    )


def downgrade() -> None:
    op.drop_column("notes", "archived")
    op.drop_column("notes", "pinned")
    op.drop_column("notes", "tags")
    op.drop_column("notes", "title")
