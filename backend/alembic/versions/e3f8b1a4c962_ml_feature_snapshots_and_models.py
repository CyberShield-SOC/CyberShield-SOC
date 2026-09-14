"""ml feature snapshots and models (IsolationForest pilot)

Revision ID: e3f8b1a4c962
Revises: d7a1c3e5f820
Create Date: 2026-09-14 00:30:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "e3f8b1a4c962"
down_revision: Union[str, Sequence[str], None] = "d7a1c3e5f820"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "ml_feature_snapshots",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("feature_set", sa.String(length=50), nullable=False),
        sa.Column("entity_type", sa.String(length=20), nullable=False),
        sa.Column("entity_id", sa.String(length=255), nullable=False),
        sa.Column("captured_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("features", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("entity_type IN ('source_ip', 'account', 'host')", name="ck_ml_feature_snapshots_entity_type"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_ml_feature_snapshots_set_entity", "ml_feature_snapshots",
        ["feature_set", "entity_type", "entity_id", "captured_at"], unique=False,
    )
    op.create_index(
        "ix_ml_feature_snapshots_set", "ml_feature_snapshots", ["feature_set", "entity_type"], unique=False,
    )

    op.create_table(
        "ml_models",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("feature_set", sa.String(length=50), nullable=False),
        sa.Column("entity_type", sa.String(length=20), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("is_active", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("feature_names", postgresql.JSONB(), nullable=False),
        sa.Column("feature_means", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("feature_stds", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("model_bytes", sa.LargeBinary(), nullable=False),
        sa.Column("sample_count", sa.Integer(), nullable=False),
        sa.Column("contamination", sa.Float(), nullable=True),
        sa.Column("params", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("trained_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("created_by", sa.BigInteger(), nullable=True),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("feature_set", "entity_type", "version", name="uq_ml_models_set_entity_version"),
    )
    op.create_index(
        "ix_ml_models_active", "ml_models", ["feature_set", "entity_type", "is_active"], unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_ml_models_active", table_name="ml_models")
    op.drop_table("ml_models")
    op.drop_index("ix_ml_feature_snapshots_set", table_name="ml_feature_snapshots")
    op.drop_index("ix_ml_feature_snapshots_set_entity", table_name="ml_feature_snapshots")
    op.drop_table("ml_feature_snapshots")
