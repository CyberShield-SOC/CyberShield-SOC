"""create detection rule settings table

Revision ID: e2f6a9c1d4b7
Revises: a1c3e7f92b4d
Create Date: 2026-09-13 00:00:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "e2f6a9c1d4b7"
down_revision: Union[str, Sequence[str], None] = "a1c3e7f92b4d"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "detection_rule_settings",
        sa.Column("rule_name", sa.String(length=60), nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("threshold", sa.Integer(), nullable=True),
        sa.Column("fail_threshold", sa.Integer(), nullable=True),
        sa.Column("window_seconds", sa.Integer(), nullable=True),
        sa.Column("success_window_seconds", sa.Integer(), nullable=True),
        sa.Column("updated_by", sa.BigInteger(), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["updated_by"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("rule_name"),
    )


def downgrade() -> None:
    op.drop_table("detection_rule_settings")
