"""add_health_tracking_to_services

Revision ID: 5d5c1de8506b
Revises: 59fe4d35b811
Create Date: 2026-01-25 18:31:37.687142

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '5d5c1de8506b'
down_revision: Union[str, None] = '59fe4d35b811'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Jira config
    op.add_column('jira_config', sa.Column('last_health_check', sa.DateTime(timezone=True), nullable=True))
    op.add_column('jira_config', sa.Column('last_health_status', sa.String(length=20), nullable=True))
    op.add_column('jira_config', sa.Column('health_check_error', sa.Text(), nullable=True))

    # TI config
    op.add_column('ti_source_config', sa.Column('last_health_check', sa.DateTime(timezone=True), nullable=True))
    op.add_column('ti_source_config', sa.Column('last_health_status', sa.String(length=20), nullable=True))
    op.add_column('ti_source_config', sa.Column('health_check_error', sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column('ti_source_config', 'health_check_error')
    op.drop_column('ti_source_config', 'last_health_status')
    op.drop_column('ti_source_config', 'last_health_check')
    op.drop_column('jira_config', 'health_check_error')
    op.drop_column('jira_config', 'last_health_status')
    op.drop_column('jira_config', 'last_health_check')
