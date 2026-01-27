import os
from pathlib import Path

from pydantic import field_validator
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
    JWT_SECRET_KEY: str = "dev-secret-key-change-in-prod"  # In production, ALWAYS override via env var
    SESSION_SECRET_KEY: str = "dev-session-key-change-in-prod"  # In production, ALWAYS override via env var
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 480  # 8 hours for dev

    # Authentication
    ALLOW_LOCAL_LOGIN_OVERRIDE: bool = False

    # SSO-only mode
    sso_only: bool = False

    # App
    APP_NAME: str = "CHAD"
    DEBUG: bool = False
    SETUP_COMPLETED: bool = False

    # Frontend URL (for redirects after SSO login)
    # Default "/" works for production (same origin behind reverse proxy)
    # Only set explicitly for local dev with different ports
    FRONTEND_URL: str = "/"

    # Application URL (from environment)
    # Public URL where the application is accessible
    # Used for CSRF validation, webhook URLs, SSO redirects
    APP_URL: str | None = None

    # Trusted proxies (for X-Forwarded-* headers)
    TRUSTED_PROXIES: str = "*"  # Trust all proxies in production

    @field_validator('JWT_SECRET_KEY', 'SESSION_SECRET_KEY')
    @classmethod
    def validate_secrets(cls, v: str, info) -> str:
        """Validate that secret keys are set and not default values in production."""
        if not v or v.strip() == "":
            raise ValueError(
                f"{info.field_name} must be set in environment variables. "
                f"Generate a secure random key using: openssl rand -base64 32"
            )

        # Check for known insecure default values
        insecure_defaults = [
            "dev-secret-key-change-in-prod",
            "dev-session-key-change-in-prod",
            "default-dev-key-change-in-prod",
            "secret",
            "changeme",
        ]

        if v.lower() in insecure_defaults:
            # CRITICAL: In production, reject insecure defaults outright
            # In development (DEBUG=True), allow with warning
            # We need to check if DEBUG is set in the environment
            debug_mode = os.environ.get("DEBUG", "").lower() in ("true", "1", "yes")

            if not debug_mode:
                raise ValueError(
                    f"{info.field_name} is using an insecure default value. "
                    f"This is NEVER acceptable in production. "
                    f"Generate a secure key using: openssl rand -base64 32"
                )

            # Development mode - log warning
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(
                f"{info.field_name} is using an insecure default value in DEBUG mode. "
                f"This is acceptable for development but MUST be changed in production!"
            )
        else:
            # Minimum length check (only if not using default)
            if len(v) < 32:
                raise ValueError(
                    f"{info.field_name} must be at least 32 characters long for security. "
                    f"Generate a secure key using: openssl rand -base64 32"
                )

        return v

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()
