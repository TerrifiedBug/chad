"""Make rule FK references nullable for safe rule deletion

Revision ID: 20260206a
Revises: dbf1e2c83bd2
Create Date: 2026-02-06

"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = '20260206a'
down_revision: str | None = 'dbf1e2c83bd2'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Make alerts.rule_id nullable and add SET NULL on delete
    op.alter_column('alerts', 'rule_id', existing_type=sa.UUID(), nullable=True)
    op.drop_constraint('fk_alerts_rule_id_rules', 'alerts', type_='foreignkey')
    op.create_foreign_key(
        'fk_alerts_rule_id_rules', 'alerts', 'rules',
        ['rule_id'], ['id'], ondelete='SET NULL'
    )

    # Make correlation_rules.rule_a_id nullable and add SET NULL on delete
    op.alter_column('correlation_rules', 'rule_a_id', existing_type=sa.UUID(), nullable=True)
    op.drop_constraint(
        op.f('correlation_rules_rule_a_id_fkey'), 'correlation_rules', type_='foreignkey'
    )
    op.create_foreign_key(
        'correlation_rules_rule_a_id_fkey', 'correlation_rules', 'rules',
        ['rule_a_id'], ['id'], ondelete='SET NULL'
    )

    # Make correlation_rules.rule_b_id nullable and add SET NULL on delete
    op.alter_column('correlation_rules', 'rule_b_id', existing_type=sa.UUID(), nullable=True)
    op.drop_constraint(
        op.f('correlation_rules_rule_b_id_fkey'), 'correlation_rules', type_='foreignkey'
    )
    op.create_foreign_key(
        'correlation_rules_rule_b_id_fkey', 'correlation_rules', 'rules',
        ['rule_b_id'], ['id'], ondelete='SET NULL'
    )

    # Make correlation_state.rule_id cascade delete
    op.drop_constraint(
        op.f('correlation_state_rule_id_fkey'), 'correlation_state', type_='foreignkey'
    )
    op.create_foreign_key(
        'correlation_state_rule_id_fkey', 'correlation_state', 'rules',
        ['rule_id'], ['id'], ondelete='CASCADE'
    )


def downgrade() -> None:
    # Revert correlation_state FK
    op.drop_constraint('correlation_state_rule_id_fkey', 'correlation_state', type_='foreignkey')
    op.create_foreign_key(
        op.f('correlation_state_rule_id_fkey'), 'correlation_state', 'rules',
        ['rule_id'], ['id']
    )

    # Revert correlation_rules.rule_b_id
    op.drop_constraint('correlation_rules_rule_b_id_fkey', 'correlation_rules', type_='foreignkey')
    op.create_foreign_key(
        op.f('correlation_rules_rule_b_id_fkey'), 'correlation_rules', 'rules',
        ['rule_b_id'], ['id']
    )
    op.alter_column('correlation_rules', 'rule_b_id', existing_type=sa.UUID(), nullable=False)

    # Revert correlation_rules.rule_a_id
    op.drop_constraint('correlation_rules_rule_a_id_fkey', 'correlation_rules', type_='foreignkey')
    op.create_foreign_key(
        op.f('correlation_rules_rule_a_id_fkey'), 'correlation_rules', 'rules',
        ['rule_a_id'], ['id']
    )
    op.alter_column('correlation_rules', 'rule_a_id', existing_type=sa.UUID(), nullable=False)

    # Revert alerts.rule_id
    op.drop_constraint('fk_alerts_rule_id_rules', 'alerts', type_='foreignkey')
    op.create_foreign_key(
        'fk_alerts_rule_id_rules', 'alerts', 'rules',
        ['rule_id'], ['id']
    )
    op.alter_column('alerts', 'rule_id', existing_type=sa.UUID(), nullable=False)
