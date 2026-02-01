# backend/tests/core/conftest.py
"""Pytest fixtures for core module tests.

This conftest intentionally keeps dependencies minimal to allow
unit testing core modules without database/service dependencies.
"""

import pytest


@pytest.fixture(autouse=True)
def skip_session_fixtures(request):
    """Skip session-scoped fixtures from root conftest for core tests."""
    pass
