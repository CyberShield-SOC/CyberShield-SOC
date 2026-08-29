"""create upload batches table

Revision ID: f3b1c9e4a002
Revises: a37f5b8d2c10
Create Date: 2026-08-28 00:00:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "f3b1c9e4a002"
down_revision: Union[str, Sequence[str], None] = "a37f5b8d2c10"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "upload_batches",
        sa.Column("upload_id", sa.UUID(), nullable=False),
        sa.Column("source_filename", sa.String(length=255), nullable=False),
        sa.Column("source_format", sa.String(length=50), nullable=False),
        sa.Column("mime_type", sa.String(length=150), nullable=True),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("total_lines", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("parsed_entries", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("skipped_lines", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("stored_entries", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("stored_alerts", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("uploaded_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("upload_id"),
    )
    op.create_index("ix_upload_batches_source_filename", "upload_batches", ["source_filename"], unique=False)
    op.create_index("ix_upload_batches_source_format", "upload_batches", ["source_format"], unique=False)
    op.create_index("ix_upload_batches_uploaded_at", "upload_batches", ["uploaded_at"], unique=False)

    op.execute(
        """
        INSERT INTO upload_batches (
            upload_id,
            source_filename,
            source_format,
            mime_type,
            size_bytes,
            total_lines,
            parsed_entries,
            skipped_lines,
            stored_entries,
            stored_alerts,
            uploaded_at
        )
        SELECT
            logs.upload_id,
            min(logs.source_filename) AS source_filename,
            min(logs.source_format) AS source_format,
            NULL AS mime_type,
            0 AS size_bytes,
            count(logs.id) AS total_lines,
            count(logs.id) AS parsed_entries,
            0 AS skipped_lines,
            count(logs.id) AS stored_entries,
            coalesce(alert_counts.stored_alerts, 0) AS stored_alerts,
            max(logs.ingested_at) AS uploaded_at
        FROM logs
        LEFT JOIN (
            SELECT upload_id, count(id) AS stored_alerts
            FROM alerts
            GROUP BY upload_id
        ) AS alert_counts ON alert_counts.upload_id = logs.upload_id
        GROUP BY logs.upload_id, alert_counts.stored_alerts
        """
    )


def downgrade() -> None:
    op.drop_index("ix_upload_batches_uploaded_at", table_name="upload_batches")
    op.drop_index("ix_upload_batches_source_format", table_name="upload_batches")
    op.drop_index("ix_upload_batches_source_filename", table_name="upload_batches")
    op.drop_table("upload_batches")
