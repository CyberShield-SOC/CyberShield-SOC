"""add auth expiry and incident ownership

Revision ID: b4c9d8e7f102
Revises: 239f773d1743, f94d3c72a91b
Create Date: 2026-07-15 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "b4c9d8e7f102"
down_revision: Union[str, Sequence[str], None] = (
    "239f773d1743",
    "f94d3c72a91b",
)
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "auth_sessions",
        sa.Column(
            "expires_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.execute(
        """
        UPDATE auth_sessions
        SET expires_at = created_at + INTERVAL '60 minutes'
        WHERE expires_at IS NULL
        """
    )
    op.alter_column(
        "auth_sessions",
        "expires_at",
        nullable=False,
    )

    op.add_column(
        "incidents",
        sa.Column(
            "created_by_user_id",
            sa.BigInteger(),
            nullable=True,
        ),
    )
    op.add_column(
        "incidents",
        sa.Column(
            "updated_by_user_id",
            sa.BigInteger(),
            nullable=True,
        ),
    )
    op.create_foreign_key(
        "fk_incidents_created_by_user_id_users",
        "incidents",
        "users",
        ["created_by_user_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_foreign_key(
        "fk_incidents_updated_by_user_id_users",
        "incidents",
        "users",
        ["updated_by_user_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index(
        "ix_incidents_created_by_user_id",
        "incidents",
        ["created_by_user_id"],
        unique=False,
    )
    op.create_index(
        "ix_incidents_updated_by_user_id",
        "incidents",
        ["updated_by_user_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_incidents_updated_by_user_id",
        table_name="incidents",
    )
    op.drop_index(
        "ix_incidents_created_by_user_id",
        table_name="incidents",
    )
    op.drop_constraint(
        "fk_incidents_updated_by_user_id_users",
        "incidents",
        type_="foreignkey",
    )
    op.drop_constraint(
        "fk_incidents_created_by_user_id_users",
        "incidents",
        type_="foreignkey",
    )
    op.drop_column("incidents", "updated_by_user_id")
    op.drop_column("incidents", "created_by_user_id")
    op.drop_column("auth_sessions", "expires_at")
