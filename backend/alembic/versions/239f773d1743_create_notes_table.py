"""create notes table"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = '239f773d1743'
down_revision: Union[str, Sequence[str], None] = 'c076a6e3cb3b'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table('notes',
    sa.Column('id', sa.BigInteger(), autoincrement=True, nullable=False),
    sa.Column('incident_id', sa.BigInteger(), nullable=False),
    sa.Column('author_user_id', sa.BigInteger(), nullable=False),
    sa.Column('body', sa.Text(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint('char_length(btrim(body)) > 0', name='ck_notes_body_not_blank'),
    sa.ForeignKeyConstraint(['author_user_id'], ['users.id'], ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_notes_author_user_id', 'notes', ['author_user_id'], unique=False)
    op.create_index('ix_notes_created_at', 'notes', ['created_at'], unique=False)
    op.create_index('ix_notes_incident_id', 'notes', ['incident_id'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index('ix_notes_incident_id', table_name='notes')
    op.drop_index('ix_notes_created_at', table_name='notes')
    op.drop_index('ix_notes_author_user_id', table_name='notes')
    op.drop_table('notes')
