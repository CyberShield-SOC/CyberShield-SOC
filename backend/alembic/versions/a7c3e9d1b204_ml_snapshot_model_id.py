"""ml feature snapshots: record which model version produced each score"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "a7c3e9d1b204"
down_revision: Union[str, Sequence[str], None] = "c1a2d8e4f6b0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Scores from different model versions are not comparable, and a score
    # can only be explained against the means/stds of the model that produced
    # it. Before this column, GET /ml/anomalies approximated "scored by the
    # active model" with created_at >= active.trained_at, which breaks as
    # soon as an admin rolls back to an older version.
    op.add_column(
        "ml_feature_snapshots",
        sa.Column(
            "model_id",
            sa.BigInteger(),
            sa.ForeignKey("ml_models.id", ondelete="SET NULL", name="fk_ml_feature_snapshots_model_id"),
            nullable=True,
        ),
    )
    op.create_index(
        "ix_ml_feature_snapshots_model_score", "ml_feature_snapshots",
        ["model_id", "score"], unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_ml_feature_snapshots_model_score", table_name="ml_feature_snapshots")
    op.drop_constraint("fk_ml_feature_snapshots_model_id", "ml_feature_snapshots", type_="foreignkey")
    op.drop_column("ml_feature_snapshots", "model_id")
