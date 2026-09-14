"""detection rule schema v2: mitre technique, confidence, entity pivot, cooldown/allowlist config

Revision ID: c4e8b2f19a06
Revises: b7d4f1a83c9e
Create Date: 2026-09-13 22:00:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "c4e8b2f19a06"
down_revision: Union[str, Sequence[str], None] = "b7d4f1a83c9e"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("alerts", sa.Column("hostname", sa.String(length=255), nullable=True))
    op.add_column("alerts", sa.Column("mitre_technique", sa.String(length=20), nullable=True))
    op.add_column(
        "alerts",
        sa.Column("confidence", sa.Integer(), server_default=sa.text("70"), nullable=False),
    )
    op.add_column(
        "alerts",
        sa.Column("entity_type", sa.String(length=20), server_default=sa.text("'source_ip'"), nullable=False),
    )
    op.add_column("alerts", sa.Column("entity_id", sa.String(length=255), nullable=True))
    op.create_check_constraint(
        "ck_alerts_entity_type",
        "alerts",
        "entity_type IN ('source_ip', 'account', 'host')",
    )
    op.create_index(
        "ix_alerts_rule_entity",
        "alerts",
        ["rule", "entity_type", "entity_id"],
        unique=False,
    )

    op.add_column("detection_rule_settings", sa.Column("cooldown_seconds", sa.Integer(), nullable=True))
    op.add_column("detection_rule_settings", sa.Column("confidence", sa.Integer(), nullable=True))
    op.add_column("detection_rule_settings", sa.Column("allowlist", postgresql.JSONB(), nullable=True))
    op.add_column("detection_rule_settings", sa.Column("start_hour", sa.Integer(), nullable=True))
    op.add_column("detection_rule_settings", sa.Column("end_hour", sa.Integer(), nullable=True))

    # Per-entity historical state (last-seen timestamps, recent-host sets,
    # ...) carried across uploads. See app/repositories/baseline_repository.py.
    op.create_table(
        "entity_baselines",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("entity_type", sa.String(length=20), nullable=False),
        sa.Column("entity_id", sa.String(length=255), nullable=False),
        sa.Column("baseline_key", sa.String(length=100), nullable=False),
        sa.Column("value", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint(
            "entity_type IN ('source_ip', 'account', 'host')",
            name="ck_entity_baselines_entity_type",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ux_entity_baselines_entity_key",
        "entity_baselines",
        ["entity_type", "entity_id", "baseline_key"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("ux_entity_baselines_entity_key", table_name="entity_baselines")
    op.drop_table("entity_baselines")

    op.drop_column("detection_rule_settings", "end_hour")
    op.drop_column("detection_rule_settings", "start_hour")
    op.drop_column("detection_rule_settings", "allowlist")
    op.drop_column("detection_rule_settings", "confidence")
    op.drop_column("detection_rule_settings", "cooldown_seconds")

    op.drop_index("ix_alerts_rule_entity", table_name="alerts")
    op.drop_constraint("ck_alerts_entity_type", "alerts", type_="check")
    op.drop_column("alerts", "entity_id")
    op.drop_column("alerts", "entity_type")
    op.drop_column("alerts", "confidence")
    op.drop_column("alerts", "mitre_technique")
    op.drop_column("alerts", "hostname")
