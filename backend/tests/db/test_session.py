# backend/tests/db/test_session.py
"""Tests for database session configuration."""

import os
from unittest.mock import patch


def test_pool_size_from_env():
    """Pool size should be configurable via DATABASE_POOL_SIZE."""
    with patch.dict(os.environ, {"DATABASE_POOL_SIZE": "30"}):
        # Re-import to pick up new env
        import importlib
        from app.db import session
        importlib.reload(session)

        assert session.pool_size == 30


def test_pool_size_default():
    """Pool size should default to 20."""
    with patch.dict(os.environ, {}, clear=False):
        # Remove the env var if set
        os.environ.pop("DATABASE_POOL_SIZE", None)

        import importlib
        from app.db import session
        importlib.reload(session)

        assert session.pool_size == 20


def test_max_overflow_from_env():
    """Max overflow should be configurable via DATABASE_MAX_OVERFLOW."""
    with patch.dict(os.environ, {"DATABASE_MAX_OVERFLOW": "50"}):
        import importlib
        from app.db import session
        importlib.reload(session)

        assert session.max_overflow == 50


def test_max_overflow_default():
    """Max overflow should default to 40."""
    with patch.dict(os.environ, {}, clear=False):
        os.environ.pop("DATABASE_MAX_OVERFLOW", None)

        import importlib
        from app.db import session
        importlib.reload(session)

        assert session.max_overflow == 40
