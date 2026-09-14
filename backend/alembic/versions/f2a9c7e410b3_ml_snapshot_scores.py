"""ml feature snapshots: add score column for shadow-mode review

Revision ID: f2a9c7e410b3
Revises: e3f8b1a4c962
Create Date: 2026-09-14 01:15:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "f2a9c7e410b3"
down_revision: Union[str, Sequence[str], None] = "e3f8b1a4c962"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("ml_feature_snapshots", sa.Column("score", sa.Float(), nullable=True))
    # Shadow-mode review pulls the lowest (most anomalous) scores for a
    # feature_set/entity_type — see GET /ml/scores.
    op.create_index(
        "ix_ml_feature_snapshots_score", "ml_feature_snapshots",
        ["feature_set", "entity_type", "score"], unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_ml_feature_snapshots_score", table_name="ml_feature_snapshots")
    op.drop_column("ml_feature_snapshots", "score")
