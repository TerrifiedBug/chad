"""add jira config

Revision ID: 02695b14ed48
Revises: 2ef7556b4828
Create Date: 2026-01-24 17:51:34.211289

"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = '02695b14ed48'
down_revision: str | None = '2ef7556b4828'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table('jira_config',
    sa.Column('jira_url', sa.String(length=255), nullable=False),
    sa.Column('email', sa.String(length=255), nullable=False),
    sa.Column('api_token_encrypted', sa.String(length=500), nullable=False),
    sa.Column('default_project', sa.String(length=50), nullable=False),
    sa.Column('default_issue_type', sa.String(length=50), nullable=False),
    sa.Column('is_enabled', sa.Boolean(), nullable=False),
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )


def downgrade() -> None:
    op.drop_table('jira_config')
