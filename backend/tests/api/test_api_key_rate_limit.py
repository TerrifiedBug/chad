"""Tests for API key rate limiting."""

import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import get_password_hash
from app.models.api_key import APIKey, generate_api_key
from app.models.user import User, UserRole


@pytest.mark.asyncio
async def test_api_key_rate_limit_enforced(
    client: AsyncClient,
    test_session: AsyncSession,
):
    """API key requests are rate limited per key."""
    # Create a user and API key
    user = User(
        id=uuid.uuid4(),
        email="api-user@example.com",
        password_hash=get_password_hash("password"),
        role=UserRole.ADMIN,
        is_active=True,
    )
    test_session.add(user)
    await test_session.commit()

    raw_key = generate_api_key()
    key_prefix = raw_key[:12]
    key_hash = get_password_hash(raw_key)

    api_key = APIKey(
        name="Test API Key",
        key_hash=key_hash,
        key_prefix=key_prefix,
        user_id=user.id,
        is_active=True,
    )
    test_session.add(api_key)
    await test_session.commit()

    # Mock Redis to simulate rate limit reached
    from unittest.mock import MagicMock

    async def mock_get_redis():
        mock_redis = AsyncMock()
        mock_pipeline = AsyncMock()

        # Mock the pipeline methods to return the pipeline itself (for chaining)
        # Use MagicMock for non-async methods
        mock_pipeline.zremrangebyscore = MagicMock(return_value=mock_pipeline)
        mock_pipeline.zcard = MagicMock(return_value=mock_pipeline)
        mock_pipeline.zadd = MagicMock(return_value=mock_pipeline)
        mock_pipeline.expire = MagicMock(return_value=mock_pipeline)

        # Mock execute to return proper results
        # First execute has 2 results: [zremrangebyscore_result, zcard_result]
        mock_pipeline.execute = AsyncMock(
            return_value=[None, 100],  # zremrangebyscore (None), zcard (100 requests)
        )
        # pipeline() should be a non-async method
        mock_redis.pipeline = MagicMock(return_value=mock_pipeline)
        return mock_redis

    with patch("app.services.api_rate_limit.get_redis", side_effect=mock_get_redis):
        response = await client.get(
            "/api/external/stats",
            headers={"X-API-Key": raw_key},
        )

        # Should return 429 when rate limit exceeded
        assert response.status_code == 429
        assert "Rate limit exceeded" in response.json()["detail"]
        assert response.headers.get("Retry-After") == "60"


@pytest.mark.asyncio
async def test_api_key_rate_limit_allows_under_limit(
    client: AsyncClient,
    test_session: AsyncSession,
):
    """API key requests are allowed when under rate limit."""
    # Create a user and API key
    user = User(
        id=uuid.uuid4(),
        email="api-user2@example.com",
        password_hash=get_password_hash("password"),
        role=UserRole.ADMIN,
        is_active=True,
    )
    test_session.add(user)
    await test_session.commit()

    raw_key = generate_api_key()
    key_prefix = raw_key[:12]
    key_hash = get_password_hash(raw_key)

    api_key = APIKey(
        name="Test API Key 2",
        key_hash=key_hash,
        key_prefix=key_prefix,
        user_id=user.id,
        is_active=True,
    )
    test_session.add(api_key)
    await test_session.commit()

    # Mock Redis to simulate under rate limit
    from unittest.mock import MagicMock

    async def mock_get_redis():
        mock_redis = AsyncMock()
        mock_pipeline = AsyncMock()

        # Mock the pipeline methods to return the pipeline itself (for chaining)
        mock_pipeline.zremrangebyscore = MagicMock(return_value=mock_pipeline)
        mock_pipeline.zcard = MagicMock(return_value=mock_pipeline)
        mock_pipeline.zadd = MagicMock(return_value=mock_pipeline)
        mock_pipeline.expire = MagicMock(return_value=mock_pipeline)

        mock_pipeline.execute = AsyncMock(
            side_effect=[
                [None, 50],  # First execute: zremrangebyscore (None), zcard (50 requests)
                [None, None],  # Second execute: zadd (None), expire (None)
            ]
        )
        # pipeline() should be a non-async method
        mock_redis.pipeline = MagicMock(return_value=mock_pipeline)
        return mock_redis

    with patch("app.services.api_rate_limit.get_redis", side_effect=mock_get_redis):
        response = await client.get(
            "/api/external/stats",
            headers={"X-API-Key": raw_key},
        )

        # Should succeed when under rate limit
        assert response.status_code == 200


@pytest.mark.asyncio
async def test_api_key_rate_limit_different_keys_separate_limits(
    client: AsyncClient,
    test_session: AsyncSession,
):
    """Different API keys have separate rate limits."""
    # Create two users with API keys
    user1 = User(
        id=uuid.uuid4(),
        email="user1@example.com",
        password_hash=get_password_hash("password"),
        role=UserRole.ADMIN,
        is_active=True,
    )
    user2 = User(
        id=uuid.uuid4(),
        email="user2@example.com",
        password_hash=get_password_hash("password"),
        role=UserRole.ADMIN,
        is_active=True,
    )
    test_session.add_all([user1, user2])
    await test_session.commit()

    raw_key1 = generate_api_key()
    key_prefix1 = raw_key1[:12]
    key_hash1 = get_password_hash(raw_key1)

    raw_key2 = generate_api_key()
    key_prefix2 = raw_key2[:12]
    key_hash2 = get_password_hash(raw_key2)

    api_key1 = APIKey(
        name="Key 1",
        key_hash=key_hash1,
        key_prefix=key_prefix1,
        user_id=user1.id,
        is_active=True,
    )
    api_key2 = APIKey(
        name="Key 2",
        key_hash=key_hash2,
        key_prefix=key_prefix2,
        user_id=user2.id,
        is_active=True,
    )
    test_session.add_all([api_key1, api_key2])
    await test_session.commit()

    # Mock Redis to simulate key1 at limit, key2 under limit
    from unittest.mock import MagicMock

    # Track call count across get_redis calls
    call_count = [0]

    async def mock_get_redis():
        call_count[0] += 1

        mock_redis = AsyncMock()
        mock_pipeline = AsyncMock()

        # Mock the pipeline methods to return the pipeline itself (for chaining)
        mock_pipeline.zremrangebyscore = MagicMock(return_value=mock_pipeline)
        mock_pipeline.zcard = MagicMock(return_value=mock_pipeline)
        mock_pipeline.zadd = MagicMock(return_value=mock_pipeline)
        mock_pipeline.expire = MagicMock(return_value=mock_pipeline)

        # First call (key1): at limit
        if call_count[0] == 1:
            mock_pipeline.execute = AsyncMock(
                return_value=[None, 100],  # zcard returns 100
            )
        # Second call (key2): under limit
        else:
            mock_pipeline.execute = AsyncMock(
                side_effect=[
                    [None, 50],  # First execute: zcard returns 50
                    [None, None],  # Second execute: zadd, expire
                ]
            )

        # pipeline() should be a non-async method
        mock_redis.pipeline = MagicMock(return_value=mock_pipeline)
        return mock_redis

    with patch("app.services.api_rate_limit.get_redis", side_effect=mock_get_redis):
        # Key 1 should be rate limited
        response1 = await client.get(
            "/api/external/stats",
            headers={"X-API-Key": raw_key1},
        )
        assert response1.status_code == 429

        # Key 2 should still work (separate limit)
        response2 = await client.get(
            "/api/external/stats",
            headers={"X-API-Key": raw_key2},
        )
        assert response2.status_code == 200


@pytest.mark.asyncio
async def test_api_key_rate_limit_inactive_key_rejected(
    client: AsyncClient,
    test_session: AsyncSession,
):
    """Inactive API keys are rejected before rate limiting."""
    user = User(
        id=uuid.uuid4(),
        email="inactive-user@example.com",
        password_hash=get_password_hash("password"),
        role=UserRole.ADMIN,
        is_active=True,
    )
    test_session.add(user)
    await test_session.commit()

    raw_key = generate_api_key()
    key_prefix = raw_key[:12]
    key_hash = get_password_hash(raw_key)

    api_key = APIKey(
        name="Inactive Key",
        key_hash=key_hash,
        key_prefix=key_prefix,
        user_id=user.id,
        is_active=False,  # Inactive
    )
    test_session.add(api_key)
    await test_session.commit()

    response = await client.get(
        "/api/external/stats",
        headers={"X-API-Key": raw_key},
    )

    # Should return 401 for inactive key (before rate limiting)
    assert response.status_code == 401
    assert "Invalid or expired API key" in response.json()["detail"]


@pytest.mark.asyncio
async def test_api_key_rate_limit_expired_key_rejected(
    client: AsyncClient,
    test_session: AsyncSession,
):
    """Expired API keys are rejected before rate limiting."""
    user = User(
        id=uuid.uuid4(),
        email="expired-user@example.com",
        password_hash=get_password_hash("password"),
        role=UserRole.ADMIN,
        is_active=True,
    )
    test_session.add(user)
    await test_session.commit()

    raw_key = generate_api_key()
    key_prefix = raw_key[:12]
    key_hash = get_password_hash(raw_key)

    api_key = APIKey(
        name="Expired Key",
        key_hash=key_hash,
        key_prefix=key_prefix,
        user_id=user.id,
        is_active=True,
        expires_at=datetime.now(UTC) - timedelta(days=1),  # Expired
    )
    test_session.add(api_key)
    await test_session.commit()

    response = await client.get(
        "/api/external/stats",
        headers={"X-API-Key": raw_key},
    )

    # Should return 401 for expired key (before rate limiting)
    assert response.status_code == 401
    assert "Invalid or expired API key" in response.json()["detail"]


@pytest.mark.asyncio
async def test_api_key_rate_limit_fails_open_on_redis_error(
    client: AsyncClient,
    test_session: AsyncSession,
):
    """Rate limiter fails open if Redis is unavailable."""
    user = User(
        id=uuid.uuid4(),
        email="failopen-user@example.com",
        password_hash=get_password_hash("password"),
        role=UserRole.ADMIN,
        is_active=True,
    )
    test_session.add(user)
    await test_session.commit()

    raw_key = generate_api_key()
    key_prefix = raw_key[:12]
    key_hash = get_password_hash(raw_key)

    api_key = APIKey(
        name="Fail Open Key",
        key_hash=key_hash,
        key_prefix=key_prefix,
        user_id=user.id,
        is_active=True,
    )
    test_session.add(api_key)
    await test_session.commit()

    # Mock Redis to raise an exception
    async def mock_get_redis():
        mock_redis = AsyncMock()
        mock_redis.pipeline.side_effect = Exception("Redis connection failed")
        return mock_redis

    with patch("app.services.api_rate_limit.get_redis", side_effect=mock_get_redis):
        response = await client.get(
            "/api/external/stats",
            headers={"X-API-Key": raw_key},
        )

        # Should succeed (fail open) when Redis is unavailable
        assert response.status_code == 200
