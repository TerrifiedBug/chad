"""maker-checker hardening: multi-approver quorum + approval deadline

Revision ID: 20260614g
Revises: 20260614f
Create Date: 2026-06-15 09:10:00.000000

Additive. Adds:
  - deployment_requests.required_approvals  : quorum size (default 1 = today)
  - deployment_requests.approval_deadline   : optional approval SLA deadline
  - deployment_request_approvals            : one row per checker's approval

All back-compatible: existing requests default required_approvals=1, which is
the current single-checker behaviour.
"""
from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = '20260614g'
down_revision: str | None = '20260614f'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        'deployment_requests',
        sa.Column('required_approvals', sa.Integer(), nullable=False, server_default='1'),
    )
    op.add_column(
        'deployment_requests',
        sa.Column('approval_deadline', sa.DateTime(timezone=True), nullable=True),
    )
    op.create_table(
        'deployment_request_approvals',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('request_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('approver_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('note', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('request_id', 'approver_id', name='uq_deployment_request_approval'),
        sa.ForeignKeyConstraint(['request_id'], ['deployment_requests.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['approver_id'], ['users.id'], ondelete='CASCADE'),
    )
    op.create_index(
        'ix_deployment_request_approvals_request_id', 'deployment_request_approvals', ['request_id']
    )


def downgrade() -> None:
    op.drop_index('ix_deployment_request_approvals_request_id', table_name='deployment_request_approvals')
    op.drop_table('deployment_request_approvals')
    op.drop_column('deployment_requests', 'approval_deadline')
    op.drop_column('deployment_requests', 'required_approvals')
