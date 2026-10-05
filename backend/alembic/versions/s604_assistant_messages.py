"""Persist AI assistant conversations per analyst."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "s604_assistant_messages"
down_revision = "s603_incidents"
branch_labels = depends_on = None


def upgrade():
    op.create_table(
        "assistant_messages",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("user_id", sa.BigInteger(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("role", sa.String(10), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("tools_used", postgresql.ARRAY(sa.String(100)), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("role IN ('user', 'assistant')", name="ck_assistant_messages_role"),
        sa.CheckConstraint("char_length(btrim(body)) > 0", name="ck_assistant_messages_body_not_blank"),
    )
    op.create_index("ix_assistant_messages_user_id_id", "assistant_messages", ["user_id", "id"])


def downgrade():
    op.drop_index("ix_assistant_messages_user_id_id", table_name="assistant_messages")
    op.drop_table("assistant_messages")
