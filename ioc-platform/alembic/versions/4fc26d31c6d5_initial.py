"""initial

Revision ID: 4fc26d31c6d5
Revises:
Create Date: 2026-07-30 19:43:28.549623

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '4fc26d31c6d5'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "investigations",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "iocs",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("value", sa.String(512), nullable=False),
        sa.Column("ioc_type", sa.String(50), nullable=False),
        sa.Column("first_seen", sa.DateTime(), nullable=True),
        sa.Column("last_seen", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("value", name="uq_ioc_value"),
    )
    op.create_index("ix_iocs_value", "iocs", ["value"])
    op.create_table(
        "investigation_iocs",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("investigation_id", sa.Integer(), nullable=False),
        sa.Column("ioc_id", sa.Integer(), nullable=False),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["investigation_id"], ["investigations.id"], ),
        sa.ForeignKeyConstraint(["ioc_id"], ["iocs.id"], ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "lookup_results",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("ioc_id", sa.Integer(), nullable=False),
        sa.Column("task_id", sa.String(32), nullable=False),
        sa.Column("composite_score", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("composite_verdict", sa.String(20), nullable=False, server_default="unknown"),
        sa.Column("composite_confidence", sa.String(10), nullable=False, server_default="low"),
        sa.Column("full_response", sa.Text(), nullable=True),
        sa.Column("source_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["ioc_id"], ["iocs.id"], ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_lookup_results_task_id", "lookup_results", ["task_id"])


def downgrade() -> None:
    op.drop_table("lookup_results")
    op.drop_table("investigation_iocs")
    op.drop_table("iocs")
    op.drop_table("investigations")
