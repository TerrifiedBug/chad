"""add_auth_token_to_index_patterns

Revision ID: d7e9f1a2b3c4
Revises: b5c8a0b4123d
Create Date: 2026-01-22 18:30:00.000000

"""
import secrets
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd7e9f1a2b3c4'
down_revision: Union[str, None] = 'b5c8a0b4123d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add auth_token column with a default for new rows
    op.add_column(
        'index_patterns',
        sa.Column('auth_token', sa.String(64), nullable=True)
    )

    # Generate unique tokens for any existing rows
    connection = op.get_bind()
    result = connection.execute(
        sa.text("SELECT id FROM index_patterns WHERE auth_token IS NULL")
    )
    for row in result:
        token = secrets.token_urlsafe(32)
        connection.execute(
            sa.text("UPDATE index_patterns SET auth_token = :token WHERE id = :id"),
            {"token": token, "id": row[0]}
        )

    # Now make the column NOT NULL
    op.alter_column(
        'index_patterns',
        'auth_token',
        existing_type=sa.String(64),
        nullable=False
    )


def downgrade() -> None:
    op.drop_column('index_patterns', 'auth_token')
