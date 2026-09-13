"""add blocked ips and log ports

Revision ID: 7c91d4e6a2b8
Revises: f3b1c9e4a002
Create Date: 2026-09-12 01:45:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '7c91d4e6a2b8'
down_revision: Union[str, None] = 'f3b1c9e4a002'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Add port column to logs table
    op.add_column('logs', sa.Column('port', sa.Integer(), nullable=True))
    op.create_index('ix_logs_port', 'logs', ['port'], unique=False)

    # 2. Add blocked_ips table
    op.create_table(
        'blocked_ips',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('ip', postgresql.INET(), nullable=False),
        sa.Column('rule_name', sa.String(length=150), nullable=False),
        sa.Column('reason', sa.String(length=255), nullable=False),
        sa.Column('is_active', sa.Boolean(), server_default=sa.text('true'), nullable=False),
        sa.Column('block_count', sa.Integer(), server_default=sa.text('1'), nullable=False),
        sa.Column('unblock_reason', sa.String(length=255), nullable=True),
        sa.Column('unblocked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('created_by', sa.String(length=100), nullable=True),
        sa.Column('updated_by', sa.String(length=100), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('ip')
    )
    op.create_index('ix_blocked_ips_ip', 'blocked_ips', ['ip'], unique=True)


def downgrade() -> None:
    # 1. Drop blocked_ips table
    op.drop_index('ix_blocked_ips_ip', table_name='blocked_ips')
    op.drop_table('blocked_ips')

    # 2. Remove port column from logs table
    op.drop_index('ix_logs_port', table_name='logs')
    op.drop_column('logs', 'port')
