"""add deployment requests (dual-control approval)

Revision ID: 20260613c
Revises: 20260613b
Create Date: 2026-06-13 22:30:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = '20260613c'
down_revision: str | None = '20260613b'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        'deployment_requests',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.Column('requested_by', sa.UUID(), nullable=False),
        sa.Column('reviewed_by', sa.UUID(), nullable=True),
        sa.Column('change_reason', sa.Text(), nullable=False),
        sa.Column('review_note', sa.Text(), nullable=True),
        sa.Column('team_id', sa.UUID(), nullable=True),
        sa.Column('target_environment_id', sa.UUID(), nullable=True),
        sa.Column('reviewed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('applied_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['requested_by'], ['users.id']),
        sa.ForeignKeyConstraint(['reviewed_by'], ['users.id']),
        sa.ForeignKeyConstraint(['team_id'], ['teams.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_deployment_requests_status', 'deployment_requests', ['status'])
    op.create_index('ix_deployment_requests_requested_by', 'deployment_requests', ['requested_by'])
    op.create_index('ix_deployment_requests_team_id', 'deployment_requests', ['team_id'])

    op.create_table(
        'deployment_request_items',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('request_id', sa.UUID(), nullable=False),
        sa.Column('rule_id', sa.UUID(), nullable=True),
        sa.Column('correlation_rule_id', sa.UUID(), nullable=True),
        sa.Column('rule_version_id', sa.UUID(), nullable=True),
        sa.Column('version_number', sa.Integer(), nullable=False),
        sa.Column('kind', sa.String(length=20), nullable=False),
        sa.Column('apply_status', sa.String(length=20), nullable=True),
        sa.Column('apply_error', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['request_id'], ['deployment_requests.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['rule_id'], ['rules.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['correlation_rule_id'], ['correlation_rules.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['rule_version_id'], ['rule_versions.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_deployment_request_items_request_id', 'deployment_request_items', ['request_id'])
    op.create_index('ix_deployment_request_items_rule_id', 'deployment_request_items', ['rule_id'])
    op.create_index(
        'ix_deployment_request_items_correlation_rule_id',
        'deployment_request_items',
        ['correlation_rule_id'],
    )

    op.add_column(
        'notification_settings',
        sa.Column(
            'require_deploy_approval',
            sa.Boolean(),
            server_default=sa.text('false'),
            nullable=False,
        ),
    )


def downgrade() -> None:
    op.drop_column('notification_settings', 'require_deploy_approval')
    op.drop_index('ix_deployment_request_items_correlation_rule_id', table_name='deployment_request_items')
    op.drop_index('ix_deployment_request_items_rule_id', table_name='deployment_request_items')
    op.drop_index('ix_deployment_request_items_request_id', table_name='deployment_request_items')
    op.drop_table('deployment_request_items')
    op.drop_index('ix_deployment_requests_team_id', table_name='deployment_requests')
    op.drop_index('ix_deployment_requests_requested_by', table_name='deployment_requests')
    op.drop_index('ix_deployment_requests_status', table_name='deployment_requests')
    op.drop_table('deployment_requests')
