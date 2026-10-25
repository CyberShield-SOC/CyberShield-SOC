"""Persist collector provenance on upload batches, preserving existing uploads."""
from alembic import op
import sqlalchemy as sa

revision = "s702_ingestion_metadata"
down_revision = "s604_assistant_messages"
branch_labels = depends_on = None


def upgrade():
    op.add_column("upload_batches", sa.Column("source_name", sa.String(255), nullable=True))
    op.add_column("upload_batches", sa.Column("source_type", sa.String(20), nullable=True))
    op.add_column("upload_batches", sa.Column("source_host", sa.String(255), nullable=True))
    op.add_column("upload_batches", sa.Column("ingested_by", sa.BigInteger(), nullable=True))
    op.create_foreign_key("fk_upload_batches_ingested_by", "upload_batches", "users", ["ingested_by"], ["id"], ondelete="SET NULL")


def downgrade():
    op.drop_constraint("fk_upload_batches_ingested_by", "upload_batches", type_="foreignkey")
    for name in ("ingested_by", "source_host", "source_type", "source_name"):
        op.drop_column("upload_batches", name)
