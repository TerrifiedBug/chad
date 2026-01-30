# backend/tests/db/conftest.py
"""Pytest fixtures for db module tests.

This conftest allows unit testing db configuration without database connections.
"""

import pytest


@pytest.fixture(autouse=True)
def skip_session_fixtures(request):
    """Skip session-scoped fixtures from root conftest for db unit tests."""
    pass
