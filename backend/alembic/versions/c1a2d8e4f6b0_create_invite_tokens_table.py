"""create invite tokens table"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "c1a2d8e4f6b0"
down_revision: Union[str, Sequence[str], None] = "s702_ingestion_metadata"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "invite_tokens",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("role_id", sa.BigInteger(), nullable=False),
        sa.Column("invited_by_user_id", sa.BigInteger(), nullable=True),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("revoked", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["role_id"], ["roles.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["invited_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_invite_tokens_email", "invite_tokens", ["email"], unique=False)
    op.create_index("ix_invite_tokens_token_hash", "invite_tokens", ["token_hash"], unique=True)
    op.create_index(
        "ix_invite_tokens_email_used_revoked",
        "invite_tokens",
        ["email", "used", "revoked"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_invite_tokens_email_used_revoked", table_name="invite_tokens")
    op.drop_index("ix_invite_tokens_token_hash", table_name="invite_tokens")
    op.drop_index("ix_invite_tokens_email", table_name="invite_tokens")
    op.drop_table("invite_tokens")
