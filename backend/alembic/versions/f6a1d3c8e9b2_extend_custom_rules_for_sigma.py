"""extend custom rules: minimum count, ATT&CK technique, source (Sigma)"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "f6a1d3c8e9b2"
down_revision: Union[str, Sequence[str], None] = "e5f9c2b7d4a1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("custom_rules", sa.Column("min_count", sa.Integer(), server_default=sa.text("1"), nullable=False))
    op.add_column("custom_rules", sa.Column("mitre_technique", sa.String(length=20), nullable=True))
    op.add_column(
        "custom_rules",
        sa.Column("source", sa.String(length=20), server_default=sa.text("'builder'"), nullable=False),
    )
    op.add_column("custom_rules", sa.Column("external_id", sa.String(length=100), nullable=True))
    op.create_check_constraint("ck_custom_rules_source", "custom_rules", "source IN ('builder', 'sigma')")
    op.create_check_constraint("ck_custom_rules_min_count", "custom_rules", "min_count >= 1")
    op.create_index(
        "uq_custom_rules_source_external_id",
        "custom_rules",
        ["source", "external_id"],
        unique=True,
        postgresql_where=sa.text("external_id IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index("uq_custom_rules_source_external_id", table_name="custom_rules")
    op.drop_constraint("ck_custom_rules_min_count", "custom_rules", type_="check")
    op.drop_constraint("ck_custom_rules_source", "custom_rules", type_="check")
    op.drop_column("custom_rules", "external_id")
    op.drop_column("custom_rules", "source")
    op.drop_column("custom_rules", "mitre_technique")
    op.drop_column("custom_rules", "min_count")
