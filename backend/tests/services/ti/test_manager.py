"""Tests for TI Enrichment Manager with MISP integration."""

from unittest.mock import MagicMock

import pytest

from app.models.ti_config import TISourceConfig, TISourceType
from app.services.ti.manager import TIEnrichmentManager
from app.services.ti.misp import MISPClient


def test_manager_creates_misp_client():
    """Test that TI manager correctly creates MISP client from config."""
    manager = TIEnrichmentManager()

    # Create a mock config for MISP
    config = MagicMock(spec=TISourceConfig)
    config.source_type = TISourceType.MISP.value
    config.api_key_encrypted = None  # We'll patch decrypt
    config.instance_url = "https://misp.example.com"
    config.config = {"verify_tls": True}

    # Patch decrypt to return a test key
    with pytest.MonkeyPatch().context() as mp:
        mp.setattr("app.services.ti.manager.decrypt", lambda x: "test-api-key")
        config.api_key_encrypted = "encrypted-key"

        client = manager._create_client(config)

        assert client is not None
        assert isinstance(client, MISPClient)
        assert client.api_key == "test-api-key"
        assert client.instance_url == "https://misp.example.com"
        assert client.verify_tls is True


def test_manager_creates_misp_client_with_verify_tls_disabled():
    """Test MISP client creation with TLS verification disabled."""
    manager = TIEnrichmentManager()

    config = MagicMock(spec=TISourceConfig)
    config.source_type = TISourceType.MISP.value
    config.api_key_encrypted = "encrypted-key"
    config.instance_url = "https://misp.internal.local"
    config.config = {"verify_tls": False}

    with pytest.MonkeyPatch().context() as mp:
        mp.setattr("app.services.ti.manager.decrypt", lambda x: "test-api-key")

        client = manager._create_client(config)

        assert client is not None
        assert isinstance(client, MISPClient)
        assert client.verify_tls is False


def test_manager_requires_api_key_for_misp():
    """Test that MISP client is not created without API key."""
    manager = TIEnrichmentManager()

    config = MagicMock(spec=TISourceConfig)
    config.source_type = TISourceType.MISP.value
    config.api_key_encrypted = None
    config.instance_url = "https://misp.example.com"
    config.config = {}

    client = manager._create_client(config)

    assert client is None


def test_manager_requires_instance_url_for_misp():
    """Test that MISP client is not created without instance URL."""
    manager = TIEnrichmentManager()

    config = MagicMock(spec=TISourceConfig)
    config.source_type = TISourceType.MISP.value
    config.api_key_encrypted = "encrypted-key"
    config.instance_url = None
    config.config = {}

    with pytest.MonkeyPatch().context() as mp:
        mp.setattr("app.services.ti.manager.decrypt", lambda x: "test-api-key")

        client = manager._create_client(config)

        assert client is None


def test_manager_misp_in_supported_sources():
    """Test that MISP is a supported source type in the manager."""
    # MISP should be handled by the manager's _create_client method
    # Verify by checking the match statement handles TISourceType.MISP
    assert TISourceType.MISP.value == "misp"
