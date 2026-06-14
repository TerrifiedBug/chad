"""add git config-as-code sync (one-way push)

Revision ID: 20260614d
Revises: 20260614c
Create Date: 2026-06-14 16:30:00.000000

Additive + reversible. Adds:
  - environments.git_*           : per-env git sync config (push-mode only wired)
  - rules.git_path               : stable per-rule filename for the synced YAML
  - git_sync_jobs                : durable retry queue drained by the scheduler

All new environment columns are nullable or carry server_defaults, so existing
rows stay valid. No data migration needed (git sync is opt-in, default off).
"""
from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = '20260614d'
down_revision: str | None = '20260614c'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # --- environments git config -------------------------------------------
    op.add_column('environments', sa.Column('git_repo_url', sa.String(length=1024), nullable=True))
    op.add_column(
        'environments',
        sa.Column('git_branch', sa.String(length=255), nullable=False, server_default='main'),
    )
    op.add_column('environments', sa.Column('git_token_encrypted', sa.Text(), nullable=True))
    op.add_column(
        'environments',
        sa.Column('gitops_mode', sa.String(length=20), nullable=False, server_default='off'),
    )
    op.add_column('environments', sa.Column('git_provider', sa.String(length=50), nullable=True))
    op.add_column('environments', sa.Column('git_webhook_secret_encrypted', sa.Text(), nullable=True))

    # --- rules.git_path -----------------------------------------------------
    op.add_column('rules', sa.Column('git_path', sa.String(length=512), nullable=True))

    # --- git_sync_jobs ------------------------------------------------------
    op.create_table(
        'git_sync_jobs',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('environment_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('rule_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('action', sa.String(length=20), nullable=False),
        sa.Column('file_path', sa.String(length=512), nullable=False),
        sa.Column('yaml_content', sa.Text(), nullable=True),
        sa.Column('commit_message', sa.Text(), nullable=False),
        sa.Column('author_name', sa.String(length=255), nullable=True),
        sa.Column('author_email', sa.String(length=320), nullable=True),
        sa.Column('status', sa.String(length=20), nullable=False, server_default='pending'),
        sa.Column('attempts', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('max_attempts', sa.Integer(), nullable=False, server_default='3'),
        sa.Column('last_error', sa.Text(), nullable=True),
        sa.Column('next_retry_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['environment_id'], ['environments.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['rule_id'], ['rules.id'], ondelete='SET NULL'),
    )
    op.create_index('ix_git_sync_jobs_environment_id', 'git_sync_jobs', ['environment_id'])
    op.create_index('ix_git_sync_jobs_status', 'git_sync_jobs', ['status'])


def downgrade() -> None:
    op.drop_index('ix_git_sync_jobs_status', table_name='git_sync_jobs')
    op.drop_index('ix_git_sync_jobs_environment_id', table_name='git_sync_jobs')
    op.drop_table('git_sync_jobs')
    op.drop_column('rules', 'git_path')
    op.drop_column('environments', 'git_webhook_secret_encrypted')
    op.drop_column('environments', 'git_provider')
    op.drop_column('environments', 'gitops_mode')
    op.drop_column('environments', 'git_token_encrypted')
    op.drop_column('environments', 'git_branch')
    op.drop_column('environments', 'git_repo_url')
