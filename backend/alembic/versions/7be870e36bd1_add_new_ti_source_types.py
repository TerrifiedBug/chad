"""add_new_ti_source_types

Revision ID: 7be870e36bd1
Revises: 29037f66f0ed
Create Date: 2026-01-25 21:53:46.270226

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '7be870e36bd1'
down_revision: Union[str, None] = '29037f66f0ed'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # No database schema changes needed - this migration documents the
    # addition of new TI source types to the TISourceType enum:
    # - MISP (Malware Information Sharing Platform)
    # - abuse_ch (URLhaus, Feodo Tracker)
    # - alienvault_otx (AlienVault Open Threat Exchange)
    # - phishtank (Phishing URL database)
    pass


def downgrade() -> None:
    pass
