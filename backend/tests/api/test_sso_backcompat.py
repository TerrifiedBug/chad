"""Back-compat data migration: legacy ``sso`` Setting key -> one sso_providers row.

The test DB builds schema via create_all (not alembic), so we exercise the
migration's data-copy helper directly against a real connection.
"""

import pytest
from sqlalchemy import select, text

from app.core.encryption import encrypt
from app.models.setting import Setting
from app.models.sso_provider import SSOProvider


def _load_migration_module():
    """Load the SSO migration module by file path (alembic/versions is not a package)."""
    import importlib.util
    from pathlib import Path

    path = (
        Path(__file__).resolve().parents[2]
        / "alembic"
        / "versions"
        / "20260614b_add_sso_providers_scim.py"
    )
    spec = importlib.util.spec_from_file_location("_sso_migration_under_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


async def _seed_legacy_sso(test_session, **overrides):
    value = {
        "enabled": True,
        "provider_name": "Legacy Okta",
        "issuer_url": "https://legacy.okta.example.com",
        "client_id": "legacy-client",
        "client_secret": encrypt("legacy-secret"),
        "token_auth_method": "client_secret_post",
        "scopes": "openid email profile",
        "default_role": "analyst",
        "require_email_verified": True,
        "role_mapping_enabled": True,
        "role_claim": "groups",
        "admin_values": "okta-admins",
        "analyst_values": "okta-analysts",
        "viewer_values": "okta-viewers",
    }
    value.update(overrides)
    test_session.add(Setting(key="sso", value=value))
    await test_session.commit()


@pytest.mark.asyncio
async def test_legacy_sso_key_becomes_provider(test_session):
    await _seed_legacy_sso(test_session)

    # Drive the migration's helper against this connection. We import the module
    # and run _migrate_legacy_sso_key with op bound to the live connection.
    module = _load_migration_module()

    raw_conn = await test_session.connection()

    def _apply(sync_conn):
        from alembic.migration import MigrationContext
        from alembic.operations import Operations

        ctx = MigrationContext.configure(sync_conn)
        with Operations.context(ctx):
            module._migrate_legacy_sso_key()

    await raw_conn.run_sync(_apply)
    await test_session.commit()

    provider = (
        await test_session.execute(select(SSOProvider))
    ).scalar_one_or_none()
    assert provider is not None
    assert provider.name == "Legacy Okta"
    assert provider.issuer_url == "https://legacy.okta.example.com"
    assert provider.client_id == "legacy-client"
    # Secret copied verbatim (still Fernet ciphertext, not plaintext).
    assert provider.client_secret_encrypted
    assert provider.client_secret_encrypted != "legacy-secret"
    assert provider.enabled is True
    assert provider.default_role == "analyst"
    assert provider.role_claim == "groups"
    assert provider.admin_values == "okta-admins"


@pytest.mark.asyncio
async def test_migration_idempotent(test_session):
    await _seed_legacy_sso(test_session)
    module = _load_migration_module()

    def _apply(sync_conn):
        from alembic.migration import MigrationContext
        from alembic.operations import Operations

        ctx = MigrationContext.configure(sync_conn)
        with Operations.context(ctx):
            module._migrate_legacy_sso_key()

    raw_conn = await test_session.connection()
    await raw_conn.run_sync(_apply)
    await test_session.commit()
    # Second run must NOT insert a duplicate (table already non-empty).
    raw_conn = await test_session.connection()
    await raw_conn.run_sync(_apply)
    await test_session.commit()

    count = (
        await test_session.execute(text("SELECT COUNT(*) FROM sso_providers"))
    ).scalar()
    assert count == 1


@pytest.mark.asyncio
async def test_no_legacy_key_no_provider(test_session):
    module = _load_migration_module()

    def _apply(sync_conn):
        from alembic.migration import MigrationContext
        from alembic.operations import Operations

        ctx = MigrationContext.configure(sync_conn)
        with Operations.context(ctx):
            module._migrate_legacy_sso_key()

    raw_conn = await test_session.connection()
    await raw_conn.run_sync(_apply)
    await test_session.commit()

    count = (
        await test_session.execute(text("SELECT COUNT(*) FROM sso_providers"))
    ).scalar()
    assert count == 0
