"""add audit hash chain + indexes (tamper-evidence)

Revision ID: 20260614a
Revises: 20260613c
Create Date: 2026-06-14 10:00:00.000000

Additive + reversible. Adds the forward-only hash-chain columns to audit_log,
the singleton audit_chain_tail pointer table, and the B-tree indexes that make
the audit list/filter/export paths fast. No data is altered; legacy audit_log
rows keep NULL prev_hash/hash.
"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = '20260614a'
down_revision: str | None = '20260613c'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Hash-chain columns on audit_log (nullable -> legacy rows unaffected).
    op.add_column('audit_log', sa.Column('prev_hash', sa.String(length=64), nullable=True))
    op.add_column('audit_log', sa.Column('hash', sa.String(length=64), nullable=True))

    # Singleton-per-scope chain tail pointer.
    op.create_table(
        'audit_chain_tail',
        sa.Column('scope_key', sa.String(length=32), nullable=False),
        sa.Column('last_hash', sa.String(length=64), nullable=True),
        sa.Column('last_write_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('scope_key'),
    )

    # B-tree indexes for the audit read/filter/export paths.
    op.create_index('ix_audit_log_created_at', 'audit_log', ['created_at'])
    op.create_index('ix_audit_log_action', 'audit_log', ['action'])
    op.create_index('ix_audit_log_resource_type', 'audit_log', ['resource_type'])
    op.create_index('ix_audit_log_user_id', 'audit_log', ['user_id'])
    op.create_index(
        'ix_audit_log_resource_type_created_at',
        'audit_log',
        ['resource_type', 'created_at'],
    )


def downgrade() -> None:
    op.drop_index('ix_audit_log_resource_type_created_at', table_name='audit_log')
    op.drop_index('ix_audit_log_user_id', table_name='audit_log')
    op.drop_index('ix_audit_log_resource_type', table_name='audit_log')
    op.drop_index('ix_audit_log_action', table_name='audit_log')
    op.drop_index('ix_audit_log_created_at', table_name='audit_log')
    op.drop_table('audit_chain_tail')
    op.drop_column('audit_log', 'hash')
    op.drop_column('audit_log', 'prev_hash')
