"""Encrypt secrets at rest: index_patterns.auth_token and users.totp_secret.

Widens both columns to hold Fernet ciphertext and backfills existing plaintext
rows. Idempotent: a value that already decrypts is left untouched, so re-running
(or running against a partially-migrated DB) is safe.

Revision ID: 20260613a
Revises: 20260206c
Create Date: 2026-06-13
"""

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = '20260613a'
down_revision: str | None = '20260206c'
branch_labels: str | None = None
depends_on: str | None = None


def _encrypt_existing(conn, table: str, column: str, where: str = "") -> None:
    """Encrypt any plaintext values in table.column (skip already-encrypted)."""
    from app.core.encryption import decrypt, encrypt

    rows = conn.execute(
        sa.text(f"SELECT id, {column} AS val FROM {table} {where}")  # noqa: S608 - identifiers are constants
    ).fetchall()
    for row in rows:
        val = row.val
        if not val:
            continue
        try:
            decrypt(val)
            continue  # already ciphertext
        except Exception:
            pass
        conn.execute(
            sa.text(f"UPDATE {table} SET {column} = :v WHERE id = :id"),  # noqa: S608
            {"v": encrypt(val), "id": row.id},
        )


def _decrypt_existing(conn, table: str, column: str, where: str = "") -> None:
    """Decrypt any ciphertext values back to plaintext (best-effort, for downgrade)."""
    from app.core.encryption import decrypt

    rows = conn.execute(
        sa.text(f"SELECT id, {column} AS val FROM {table} {where}")  # noqa: S608
    ).fetchall()
    for row in rows:
        val = row.val
        if not val:
            continue
        try:
            plaintext = decrypt(val)
        except Exception:
            continue  # already plaintext
        conn.execute(
            sa.text(f"UPDATE {table} SET {column} = :v WHERE id = :id"),  # noqa: S608
            {"v": plaintext, "id": row.id},
        )


def upgrade() -> None:
    # Widen first — ciphertext does not fit the original 64/32 char columns.
    op.alter_column(
        'index_patterns', 'auth_token',
        existing_type=sa.String(length=64), type_=sa.String(length=255),
        existing_nullable=False,
    )
    op.alter_column(
        'users', 'totp_secret',
        existing_type=sa.String(length=32), type_=sa.String(length=255),
        existing_nullable=True,
    )

    conn = op.get_bind()
    _encrypt_existing(conn, 'index_patterns', 'auth_token')
    _encrypt_existing(conn, 'users', 'totp_secret', where="WHERE totp_secret IS NOT NULL")


def downgrade() -> None:
    conn = op.get_bind()
    _decrypt_existing(conn, 'index_patterns', 'auth_token')
    _decrypt_existing(conn, 'users', 'totp_secret', where="WHERE totp_secret IS NOT NULL")

    op.alter_column(
        'users', 'totp_secret',
        existing_type=sa.String(length=255), type_=sa.String(length=32),
        existing_nullable=True,
    )
    op.alter_column(
        'index_patterns', 'auth_token',
        existing_type=sa.String(length=255), type_=sa.String(length=64),
        existing_nullable=False,
    )
