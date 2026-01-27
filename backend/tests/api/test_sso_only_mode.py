def test_sso_status_includes_sso_only_flag(client, admin_token):
    """Test that SSO status endpoint includes sso_only flag."""
    response = client.get(
        "/api/auth/sso/status",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "sso_only" in data
    assert isinstance(data["sso_only"], bool)
