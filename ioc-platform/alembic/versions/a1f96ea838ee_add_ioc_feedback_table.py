"""add_ioc_feedback_table

Revision ID: a1f96ea838ee
Revises: c319e9658ef8
Create Date: 2026-07-31 15:56:03.886930

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a1f96ea838ee'
down_revision: Union[str, Sequence[str], None] = 'c319e9658ef8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table('ioc_feedback',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('ioc_value', sa.String(length=512), nullable=False),
    sa.Column('feedback', sa.String(length=20), nullable=False),
    sa.Column('note', sa.Text(), nullable=True),
    sa.Column('created_at', sa.DateTime(), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.Column('updated_at', sa.DateTime(), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('ioc_value', name='uq_ioc_feedback_value')
    )
    op.create_index('ix_ioc_feedback_ioc_value', 'ioc_feedback', ['ioc_value'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index('ix_ioc_feedback_ioc_value', table_name='ioc_feedback')
    op.drop_table('ioc_feedback')
