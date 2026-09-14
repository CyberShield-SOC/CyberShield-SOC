"""detection schema v3: alert evidence, rule params, threat indicators, host heartbeats

Revision ID: d7a1c3e5f820
Revises: c4e8b2f19a06
Create Date: 2026-09-13 23:00:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "d7a1c3e5f820"
down_revision: Union[str, Sequence[str], None] = "c4e8b2f19a06"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "alerts",
        sa.Column("evidence", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False),
    )
    op.add_column("detection_rule_settings", sa.Column("params", postgresql.JSONB(), nullable=True))

    op.create_table(
        "threat_indicators",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("source", sa.String(length=100), nullable=False),
        sa.Column("indicator", sa.String(length=255), nullable=False),
        sa.Column("indicator_type", sa.String(length=10), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("created_by", sa.BigInteger(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("indicator_type IN ('ip', 'cidr', 'domain')", name="ck_threat_indicators_type"),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ux_threat_indicators_source_value", "threat_indicators", ["source", "indicator"], unique=True
    )
    op.create_index("ix_threat_indicators_indicator", "threat_indicators", ["indicator"], unique=False)

    op.create_table(
        "host_heartbeats",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("hostname", sa.String(length=255), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("cadence_seconds", sa.Float(), nullable=True),
        sa.Column("silence_alerted_for", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("hostname", name="uq_host_heartbeats_hostname"),
    )


def downgrade() -> None:
    op.drop_table("host_heartbeats")
    op.drop_index("ix_threat_indicators_indicator", table_name="threat_indicators")
    op.drop_index("ux_threat_indicators_source_value", table_name="threat_indicators")
    op.drop_table("threat_indicators")
    op.drop_column("detection_rule_settings", "params")
    op.drop_column("alerts", "evidence")
