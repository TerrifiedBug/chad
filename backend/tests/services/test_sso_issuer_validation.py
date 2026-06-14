"""validate_issuer_url: https + host required, private IPs allowed (self-hosted)."""

import pytest

from app.services.sso_providers import validate_issuer_url


def test_requires_value():
    with pytest.raises(ValueError):
        validate_issuer_url("")
    with pytest.raises(ValueError):
        validate_issuer_url(None)


def test_requires_https():
    with pytest.raises(ValueError):
        validate_issuer_url("http://idp.example.com")


def test_requires_hostname():
    with pytest.raises(ValueError):
        validate_issuer_url("https://")


def test_strips_trailing_slash():
    assert validate_issuer_url("https://idp.example.com/") == "https://idp.example.com"


def test_allows_private_ip_issuer():
    # Self-hosted IdPs (PocketID/Authentik/Keycloak) live on private networks —
    # the issuer is admin-set, so we no longer SSRF-block it.
    assert validate_issuer_url("https://192.168.1.50:1411") == "https://192.168.1.50:1411"
    assert validate_issuer_url("https://10.0.0.5") == "https://10.0.0.5"
    assert validate_issuer_url("https://pocketid.internal.lan") == "https://pocketid.internal.lan"
