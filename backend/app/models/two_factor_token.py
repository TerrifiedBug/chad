"""
Two-Factor Authentication (2FA) token storage model.

Replaces in-memory storage with database-backed persistence.
Supports both setup and login flows with automatic expiration.
"""

from datetime import datetime, timedelta, timezone

from sqlalchemy import DateTime, Index, String, select
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin


class TwoFactorToken(Base, TimestampMixin):
    """
    Store pending 2FA tokens with automatic expiration.

    This model supports two types of 2FA flows:
    1. 'setup': Initial 2FA setup where user configures TOTP
    2. 'login': Login flow where user completes TOTP challenge

    Tokens automatically expire after 10 minutes for security.
    """
    __tablename__ = "two_factor_tokens"

    # User identifier (email or user_id)
    user_id: Mapped[str] = mapped_column(String(255), primary_key=True)

    # Token type: 'setup' or 'login'
    token_type: Mapped[str] = mapped_column(String(20), primary_key=True)

    # The encrypted secret or temporary token
    token_data: Mapped[str] = mapped_column(String(500), nullable=False)

    # Expiration timestamp (default: 10 minutes from creation)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc) + timedelta(minutes=10)
    )

    # Index for efficient cleanup of expired tokens
    __table_args__ = (
        Index('ix_two_factor_tokens_expires_at', 'expires_at'),
    )

    def __repr__(self) -> str:
        return f"<TwoFactorToken(user_id={self.user_id}, type={self.token_type}, expires={self.expires_at})>"

    @property
    def is_expired(self) -> bool:
        """Check if token has expired."""
        return datetime.now(timezone.utc) > self.expires_at

    @classmethod
    async def create_token(
        cls,
        db_session,
        user_id: str,
        token_type: str,
        token_data: str,
        expires_minutes: int = 10,
    ) -> 'TwoFactorToken':
        """
        Create or update a 2FA token.

        Args:
            db_session: Database session
            user_id: User identifier (email or UUID)
            token_type: Type of token ('setup' or 'login')
            token_data: The token/secret data to store
            expires_minutes: Minutes until expiration (default: 10)

        Returns:
            Created or updated TwoFactorToken instance
        """
        # Delete any existing token of this type for this user
        await db_session.execute(
            select(cls).where(
                cls.user_id == user_id,
                cls.token_type == token_type
            )
        )
        # Create new token
        token = cls(
            user_id=user_id,
            token_type=token_type,
            token_data=token_data,
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=expires_minutes)
        )
        db_session.add(token)
        await db_session.flush()
        return token

    @classmethod
    async def get_valid_token(
        cls,
        db_session,
        user_id: str,
        token_type: str,
    ) -> 'TwoFactorToken | None':
        """
        Retrieve a valid (non-expired) token.

        Args:
            db_session: Database session
            user_id: User identifier
            token_type: Type of token ('setup' or 'login')

        Returns:
            TwoFactorToken if valid, None if expired or not found
        """
        result = await db_session.execute(
            select(cls).where(
                cls.user_id == user_id,
                cls.token_type == token_type
            )
        )
        token = result.scalar_one_or_none()

        if token and token.is_expired:
            # Delete expired token
            await db_session.delete(token)
            return None

        return token

    @classmethod
    async def delete_token(
        cls,
        db_session,
        user_id: str,
        token_type: str,
    ) -> bool:
        """
        Delete a token after use.

        Args:
            db_session: Database session
            user_id: User identifier
            token_type: Type of token to delete

        Returns:
            True if deleted, False if not found
        """
        result = await db_session.execute(
            select(cls).where(
                cls.user_id == user_id,
                cls.token_type == token_type
            )
        )
        token = result.scalar_one_or_none()

        if token:
            await db_session.delete(token)
            return True

        return False

    @classmethod
    async def cleanup_expired(cls, db_session) -> int:
        """
        Delete all expired tokens.

        Should be called periodically (e.g., via background task) to keep table clean.

        Args:
            db_session: Database session

        Returns:
            Number of tokens deleted
        """
        from sqlalchemy import delete

        stmt = delete(cls).where(cls.expires_at < datetime.now(timezone.utc))
        result = await db_session.execute(stmt)
        return result.rowcount
