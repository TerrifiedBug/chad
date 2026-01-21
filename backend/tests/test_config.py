from app.core.config import settings
from app.core.security import create_access_token, verify_password, get_password_hash


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
