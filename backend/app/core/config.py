import os
from pathlib import Path

from pydantic_settings import BaseSettings


def _get_version() -> str:
    """Read version from pyproject.toml or environment variable."""
    # First check environment variable (for Docker/CI overrides)
    if env_version := os.getenv("CHAD_VERSION"):
        return env_version

    # Try to read from pyproject.toml
    try:
        pyproject_path = Path(__file__).parent.parent.parent / "pyproject.toml"
        if pyproject_path.exists():
            content = pyproject_path.read_text()
            for line in content.split("\n"):
                if line.startswith("version"):
                    # Parse: version = "0.1.0"
                    return line.split("=")[1].strip().strip('"').strip("'")
    except Exception:
        pass

    return "0.0.0-dev"


# Application version - read from pyproject.toml, env var, or default to dev
APP_VERSION = _get_version()


class Settings(BaseSettings):
    # Database
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_USER: str = "chad"
    POSTGRES_PASSWORD: str = "devpassword"
    POSTGRES_DB: str = "chad"

    @property
    def DATABASE_URL(self) -> str:
        return (
            f"postgresql+asyncpg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

    @property
    def DATABASE_URL_SYNC(self) -> str:
        return (
            f"postgresql+psycopg2://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

    # JWT
    JWT_SECRET_KEY: str = "dev-secret-key-change-in-prod"
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 480  # 8 hours for dev

    # Authentication
    ALLOW_LOCAL_LOGIN_OVERRIDE: bool = False

    # App
    APP_NAME: str = "CHAD"
    DEBUG: bool = False
    SETUP_COMPLETED: bool = False

    # Frontend URL (for redirects after SSO login)
    # Default "/" works for production (same origin behind reverse proxy)
    # Only set explicitly for local dev with different ports
    FRONTEND_URL: str = "/"

    # Note: APP_URL is now managed via GUI in Settings > General
    # Use app.services.settings.get_app_url() to retrieve it

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()
