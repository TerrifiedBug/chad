"""add jira alert severities column

Revision ID: 968276b71c85
Revises: 02695b14ed48
Create Date: 2026-01-24 18:01:38.312510

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '968276b71c85'
down_revision: Union[str, None] = '02695b14ed48'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


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
