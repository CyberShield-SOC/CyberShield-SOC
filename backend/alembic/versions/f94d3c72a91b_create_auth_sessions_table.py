"""create auth sessions table

Revision ID: f94d3c72a91b
Revises: e106be1e97bd
Create Date: 2026-07-13 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "f94d3c72a91b"
down_revision: Union[str, Sequence[str], None] = "e106be1e97bd"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        """
        UPDATE roles
        SET name = 'Admin'
        WHERE name = 'Administrator'
          AND NOT EXISTS (SELECT 1 FROM roles WHERE name = 'Admin')
        """
    )
    op.execute(
        """
        INSERT INTO roles (name, description)
        VALUES
            ('Admin', 'Manages users, roles, and CyberShield system settings.'),
            ('Analyst', 'Reviews alerts, investigates incidents, and writes notes.'),
            ('Viewer', 'Views dashboards and security records without editing them.')
        ON CONFLICT (name) DO NOTHING
        """
    )
    op.create_table(
        "auth_sessions",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("user_id", sa.BigInteger(), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash"),
    )
    op.create_index(
        op.f("ix_auth_sessions_token_hash"),
        "auth_sessions",
        ["token_hash"],
        unique=False,
    )
    op.create_index(
        op.f("ix_auth_sessions_user_id"),
        "auth_sessions",
        ["user_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_auth_sessions_user_id"), table_name="auth_sessions")
    op.drop_index(op.f("ix_auth_sessions_token_hash"), table_name="auth_sessions")
    op.drop_table("auth_sessions")
