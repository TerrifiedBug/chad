"""Threat Intelligence integration services."""

from app.services.ti.abuse_ch import AbuseCHClient
from app.services.ti.abuseipdb import AbuseIPDBClient
from app.services.ti.alienvault_otx import AlienVaultOTXClient
from app.services.ti.base import (
    TIClient,
    TIIndicatorType,
    TILookupResult,
    TIRiskLevel,
)
from app.services.ti.greynoise import GreyNoiseClient
from app.services.ti.manager import TIEnrichmentManager, TIEnrichmentResult
from app.services.ti.misp import MISPClient
from app.services.ti.phishtank import PhishTankClient
from app.services.ti.threatfox import ThreatFoxClient
from app.services.ti.virustotal import VirusTotalClient

# IOC types and services for MISP sync
from app.services.ti.ioc_types import IOCType, IOCRecord
from app.services.ti.ioc_cache import IOCCache
from app.services.ti.ioc_index import IOCIndexService, INDICATOR_INDEX_NAME
from app.services.ti.ioc_detector import IOCDetector, IOCMatch
from app.services.ti.ioc_query_builder import IOCQueryBuilder

# MISP sync and feedback services
from app.services.ti.misp_sync import MISPIOCFetcher
from app.services.ti.misp_sync_service import MISPSyncService, MISPSyncResult
from app.services.ti.misp_feedback import MISPFeedbackService, SightingResult, EventCreationResult

__all__ = [
    # Existing TI clients
    "AbuseCHClient",
    "AbuseIPDBClient",
    "AlienVaultOTXClient",
    "GreyNoiseClient",
    "MISPClient",
    "PhishTankClient",
    "ThreatFoxClient",
    "VirusTotalClient",
    # Base TI types
    "TIClient",
    "TIEnrichmentManager",
    "TIEnrichmentResult",
    "TIIndicatorType",
    "TILookupResult",
    "TIRiskLevel",
    # IOC types
    "IOCType",
    "IOCRecord",
    # IOC services
    "IOCCache",
    "IOCIndexService",
    "INDICATOR_INDEX_NAME",
    "IOCDetector",
    "IOCMatch",
    "IOCQueryBuilder",
    # MISP services
    "MISPIOCFetcher",
    "MISPSyncService",
    "MISPSyncResult",
    "MISPFeedbackService",
    "SightingResult",
    "EventCreationResult",
]
