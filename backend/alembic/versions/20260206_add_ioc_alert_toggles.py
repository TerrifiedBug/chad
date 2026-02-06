"""Add include_ioc_alerts to notification and enrichment webhooks.

Revision ID: 20260206c
Revises: 20260206b
Create Date: 2026-02-06
"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = '20260206c'
down_revision: str | None = '20260206b'
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column(
        'alert_notification_settings',
        sa.Column('include_ioc_alerts', sa.Boolean(), nullable=False, server_default='false'),
    )
    op.add_column(
        'enrichment_webhooks',
        sa.Column('include_ioc_alerts', sa.Boolean(), nullable=False, server_default='false'),
    )


def downgrade() -> None:
    op.drop_column('enrichment_webhooks', 'include_ioc_alerts')
    op.drop_column('alert_notification_settings', 'include_ioc_alerts')
