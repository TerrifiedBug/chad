"""MISP sync service orchestrator."""

import logging
import time
from dataclasses import dataclass

from app.services.ti.ioc_cache import IOCCache
from app.services.ti.ioc_index import IOCIndexService
from app.services.ti.ioc_types import IOCType
from app.services.ti.misp_sync import MISPIOCFetcher

logger = logging.getLogger(__name__)


@dataclass
class MISPSyncResult:
    """Result of a MISP sync operation."""

    success: bool
    iocs_fetched: int = 0
    iocs_cached: int = 0
    iocs_indexed: int = 0
    expired_deleted: int = 0
    duration_ms: int = 0
    error: str | None = None


class MISPSyncService:
    """Orchestrates MISP IOC sync to Redis and OpenSearch."""

    def __init__(
        self,
        fetcher: MISPIOCFetcher,
        cache: IOCCache,
        index_service: IOCIndexService,
    ):
        """Initialize the sync service.

        Args:
            fetcher: MISP IOC fetcher instance.
            cache: Redis IOC cache instance.
            index_service: OpenSearch indicator index service.
        """
        self.fetcher = fetcher
        self.cache = cache
        self.index_service = index_service

    async def sync_iocs(
        self,
        threat_levels: list[str] | None = None,
        ioc_types: list[IOCType] | None = None,
        max_age_days: int = 30,
        tags: list[str] | None = None,
        ttl_days: int = 30,
    ) -> MISPSyncResult:
        """Sync IOCs from MISP to Redis and OpenSearch.

        Args:
            threat_levels: Filter by threat level names.
            ioc_types: Filter by IOC types.
            max_age_days: Only fetch IOCs from last N days.
            tags: Filter by MISP tags.
            ttl_days: TTL for IOCs.

        Returns:
            MISPSyncResult with sync statistics.
        """
        start_time = time.time()
        result = MISPSyncResult(success=True)

        # Step 1: Fetch IOCs from MISP
        try:
            records = await self.fetcher.fetch_iocs(
                threat_levels=threat_levels,
                ioc_types=ioc_types,
                max_age_days=max_age_days,
                tags=tags,
                ttl_days=ttl_days,
            )
            result.iocs_fetched = len(records)
            logger.info("Fetched %d IOCs from MISP", len(records))
        except Exception as e:
            logger.error("Failed to fetch IOCs from MISP: %s", e)
            result.success = False
            result.error = str(e)
            result.duration_ms = int((time.time() - start_time) * 1000)
            return result

        # Step 2: Store in Redis cache
        try:
            result.iocs_cached = await self.cache.bulk_store_iocs(records)
            logger.info("Cached %d IOCs in Redis", result.iocs_cached)
        except Exception as e:
            logger.error("Failed to cache IOCs in Redis: %s", e)
            result.success = False
            result.error = f"Redis cache failed: {e}"
            # Continue to try OpenSearch

        # Step 3: Index in OpenSearch
        try:
            result.iocs_indexed = await self.index_service.bulk_index_iocs(records)
            logger.info("Indexed %d IOCs in OpenSearch", result.iocs_indexed)
        except Exception as e:
            logger.error("Failed to index IOCs in OpenSearch: %s", e)
            result.success = False
            if result.error:
                result.error += f"; OpenSearch index failed: {e}"
            else:
                result.error = f"OpenSearch index failed: {e}"

        # Step 4: Clean up expired IOCs from index
        try:
            result.expired_deleted = await self.index_service.delete_expired_iocs()
            if result.expired_deleted > 0:
                logger.info("Deleted %d expired IOCs", result.expired_deleted)
        except Exception as e:
            logger.warning("Failed to delete expired IOCs: %s", e)
            # Non-fatal, don't mark as failed

        result.duration_ms = int((time.time() - start_time) * 1000)
        return result
