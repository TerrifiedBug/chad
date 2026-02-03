"""add_alerts_table

Revision ID: 97df79eef275
Revises: ad2c756895da
Create Date: 2026-01-28 09:36:48.765411

"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = '97df79eef275'
down_revision: str | None = 'ad2c756895da'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Create alerts table
    op.create_table(
        'alerts',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('alert_id', sa.String(length=255), nullable=False),
        sa.Column('alert_index', sa.String(length=255), nullable=False),
        sa.Column('title', sa.String(length=500), nullable=False),
        sa.Column('rule_id', sa.UUID(), nullable=False),
        sa.Column('status', sa.String(length=50), nullable=False, server_default='new'),
        sa.Column('severity', sa.String(length=50), nullable=False),
        sa.Column('acknowledged_by', sa.UUID(), nullable=True),
        sa.Column('acknowledged_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['rule_id'], ['rules.id'], name=op.f('fk_alerts_rule_id_rules')),
        sa.ForeignKeyConstraint(['acknowledged_by'], ['users.id'], name=op.f('fk_alerts_acknowledged_by_users')),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_alerts'))
    )
    op.create_index(op.f('ix_alerts_id'), 'alerts', ['id'], unique=True)
    op.create_index(op.f('ix_alerts_rule_id'), 'alerts', ['rule_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_alerts_rule_id'), table_name='alerts')
    op.drop_index(op.f('ix_alerts_id'), table_name='alerts')
    op.drop_table('alerts')
