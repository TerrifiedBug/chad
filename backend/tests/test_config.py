from app.core.config import settings
from app.core.security import create_access_token, get_password_hash, verify_password


def test_settings_loads():
    assert settings.POSTGRES_HOST is not None
    assert settings.JWT_SECRET_KEY is not None
    assert settings.JWT_ALGORITHM == "HS256"


def test_password_hashing():
    password = "testpassword123"
    hashed = get_password_hash(password)
    assert hashed != password
    assert verify_password(password, hashed)
    assert not verify_password("wrongpassword", hashed)


def test_create_access_token():
    token = create_access_token(data={"sub": "testuser"})
    assert token is not None
    assert isinstance(token, str)
    assert len(token) > 50


def test_app_url_from_environment(monkeypatch):
    """Test APP_URL can be loaded from environment variable."""
    monkeypatch.setenv("APP_URL", "https://test.example.com")
    # Reload settings to pick up env var
    from app.core.config import Settings
    test_settings = Settings()
    assert test_settings.APP_URL == "https://test.example.com"


def test_app_url_optional(monkeypatch):
    """Test APP_URL is optional (defaults to None)."""
    monkeypatch.delenv("APP_URL", raising=False)
    from app.core.config import Settings
    test_settings = Settings()
    assert test_settings.APP_URL is None
