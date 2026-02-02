"""add_health_check_config

Revision ID: 29037f66f0ed
Revises: 5d5c1de8506b
Create Date: 2026-01-25 18:32:26.848835

"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = '29037f66f0ed'
down_revision: str | None = '5d5c1de8506b'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Health check intervals
    op.add_column('notification_settings', sa.Column('jira_health_interval', sa.Integer(), nullable=True))
    op.add_column('notification_settings', sa.Column('sigmahq_health_interval', sa.Integer(), nullable=True))
    op.add_column('notification_settings', sa.Column('mitre_health_interval', sa.Integer(), nullable=True))
    op.add_column('notification_settings', sa.Column('opensearch_health_interval', sa.Integer(), nullable=True))
    op.add_column('notification_settings', sa.Column('ti_health_interval', sa.Integer(), nullable=True))

    # Health alert preferences
    op.add_column('notification_settings', sa.Column('health_alert_webhook_enabled', sa.Boolean(), nullable=True))
    op.add_column('notification_settings', sa.Column('health_alert_severity', sa.String(length=20), nullable=True))


def downgrade() -> None:
    op.drop_column('notification_settings', 'health_alert_severity')
    op.drop_column('notification_settings', 'health_alert_webhook_enabled')
    op.drop_column('notification_settings', 'ti_health_interval')
    op.drop_column('notification_settings', 'opensearch_health_interval')
    op.drop_column('notification_settings', 'mitre_health_interval')
    op.drop_column('notification_settings', 'sigmahq_health_interval')
    op.drop_column('notification_settings', 'jira_health_interval')
