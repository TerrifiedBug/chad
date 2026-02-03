"""add jira alert severities column

Revision ID: 968276b71c85
Revises: 02695b14ed48
Create Date: 2026-01-24 18:01:38.312510

"""
from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = '968276b71c85'
down_revision: str | None = '02695b14ed48'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Add alert_severities column to jira_config
    # Default to empty array - user must configure which severities to create tickets for
    op.add_column(
        'jira_config',
        sa.Column(
            'alert_severities',
            postgresql.ARRAY(sa.String()),
            nullable=False,
            server_default='{}',
        )
    )


def downgrade() -> None:
    op.drop_column('jira_config', 'alert_severities')
