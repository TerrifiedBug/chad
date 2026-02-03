import pytest


@pytest.mark.asyncio
async def test_sso_status_includes_sso_only_flag(authenticated_client):
    """Test that SSO status endpoint includes sso_only flag."""
    response = await authenticated_client.get("/api/auth/sso/status")
    assert response.status_code == 200
    data = response.json()
    assert "sso_only" in data
    assert isinstance(data["sso_only"], bool)
