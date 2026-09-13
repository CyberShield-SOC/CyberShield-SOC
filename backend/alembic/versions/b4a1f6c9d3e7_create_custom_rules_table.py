"""create custom rules table

Revision ID: b4a1f6c9d3e7
Revises: 7c91d4e6a2b8
Create Date: 2026-09-12 00:00:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "b4a1f6c9d3e7"
down_revision: Union[str, Sequence[str], None] = "7c91d4e6a2b8"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "custom_rules",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("rule_id", sa.String(length=20), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("category", sa.String(length=50), server_default=sa.text("'generic_detection'"), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("tactic", sa.String(length=20), nullable=True),
        sa.Column("conditions", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("group_by", sa.String(length=20), nullable=True),
        sa.Column("window_seconds", sa.Integer(), server_default=sa.text("600"), nullable=False),
        sa.Column("actions", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("status", sa.String(length=20), server_default=sa.text("'DRAFT'"), nullable=False),
        sa.Column("dsl", sa.Text(), nullable=True),
        sa.Column("created_by", sa.BigInteger(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')", name="ck_custom_rules_severity"),
        sa.CheckConstraint("status IN ('DRAFT', 'ENABLED', 'DISABLED')", name="ck_custom_rules_status"),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_custom_rules_rule_id", "custom_rules", ["rule_id"], unique=True)
    op.create_index("ix_custom_rules_status", "custom_rules", ["status"], unique=False)
    op.create_index("ix_custom_rules_category", "custom_rules", ["category"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_custom_rules_category", table_name="custom_rules")
    op.drop_index("ix_custom_rules_status", table_name="custom_rules")
    op.drop_index("ix_custom_rules_rule_id", table_name="custom_rules")
    op.drop_table("custom_rules")
