"""create otp verifications table

Revision ID: a1c3e7f92b4d
Revises: d0a8c2e4f6b1
Create Date: 2026-09-13 00:00:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "a1c3e7f92b4d"
down_revision: Union[str, Sequence[str], None] = "d0a8c2e4f6b1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "otp_verifications",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("user_id", sa.BigInteger(), nullable=False),
        sa.Column("pending_token_hash", sa.String(length=64), nullable=False),
        sa.Column("otp_hash", sa.String(length=64), nullable=False),
        sa.Column("remember_me", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("attempt_count", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("used", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_otp_verifications_user_id", "otp_verifications", ["user_id"], unique=False)
    op.create_index("ix_otp_verifications_pending_token_hash", "otp_verifications", ["pending_token_hash"], unique=False)
    op.create_index(
        "ix_otp_verifications_pending_token_created",
        "otp_verifications",
        ["pending_token_hash", "created_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_otp_verifications_pending_token_created", table_name="otp_verifications")
    op.drop_index("ix_otp_verifications_pending_token_hash", table_name="otp_verifications")
    op.drop_index("ix_otp_verifications_user_id", table_name="otp_verifications")
    op.drop_table("otp_verifications")
