import os

from pydantic_settings import BaseSettings

# Application version - read from environment or default to dev
APP_VERSION = os.getenv("CHAD_VERSION", "0.0.0-dev")


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
