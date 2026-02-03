"""MISP integration API endpoints."""

from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

import yaml
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_permission_dep
from app.core.encryption import decrypt
from app.db.session import get_db
from app.models.misp_imported_rule import MISPImportedRule
from app.models.rule import Rule, RuleSource, RuleStatus, RuleVersion
from app.models.ti_config import TISourceConfig, TISourceType
from app.models.user import User
from app.schemas.misp import (
    MISPConnectionStatus,
    MISPEventIOCs,
    MISPEventSummary,
    MISPImportedRuleInfo,
    MISPImportRequest,
    MISPImportResponse,
)
from app.services.attack_sync import update_rule_attack_mappings
from app.services.misp_import import MISPImportService
from app.services.misp_rule_generator import SigmaRuleGenerator

router = APIRouter(prefix="/misp", tags=["misp"])


async def get_misp_config(db: AsyncSession) -> TISourceConfig | None:
    """Get MISP TI configuration."""
    result = await db.execute(
        select(TISourceConfig).where(TISourceConfig.source_type == TISourceType.MISP)
    )
    return result.scalar_one_or_none()


async def get_misp_service(db: AsyncSession) -> MISPImportService:
    """Get configured MISP import service."""
    config = await get_misp_config(db)
    if not config or not config.is_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MISP is not configured. Configure it in Settings > Threat Intel.",
        )

    api_key = decrypt(config.api_key_encrypted) if config.api_key_encrypted else ""
    verify_ssl = config.config.get('verify_ssl', True) if config.config else True

    return MISPImportService(
        url=config.instance_url,
        api_key=api_key,
        verify_ssl=verify_ssl,
    )


@router.get("/status", response_model=MISPConnectionStatus)
async def get_misp_status(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    """Get MISP connection status."""
    config = await get_misp_config(db)

    if not config or not config.is_enabled:
        return MISPConnectionStatus(configured=False)

    try:
        service = await get_misp_service(db)
        await service.test_connection()
        await service.close()
        return MISPConnectionStatus(
            configured=True,
            connected=True,
            instance_url=config.instance_url,
        )
    except Exception as e:
        return MISPConnectionStatus(
            configured=True,
            connected=False,
            error=str(e),
            instance_url=config.instance_url,
        )


@router.get("/events", response_model=list[MISPEventSummary])
async def search_events(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    limit: int = Query(default=50, ge=1, le=200),
    date_from: str | None = None,
    date_to: str | None = None,
    threat_levels: str | None = Query(default="1,2"),  # High, Medium
    search_term: str | None = None,
):
    """Search MISP events."""
    service = await get_misp_service(db)

    try:
        threat_level_list = None
        if threat_levels:
            threat_level_list = [int(x) for x in threat_levels.split(',')]

        events = await service.search_events(
            limit=limit,
            date_from=date_from,
            date_to=date_to,
            threat_levels=threat_level_list,
            search_term=search_term,
        )
        return events
    finally:
        await service.close()


@router.get("/events/{event_id}/iocs", response_model=MISPEventIOCs)
async def get_event_iocs(
    event_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    enforce_warninglist: bool = Query(default=True),
    to_ids: bool = Query(default=True),
):
    """Get IOCs from a MISP event, grouped by type."""
    service = await get_misp_service(db)

    try:
        event = await service.get_event(event_id)
        iocs = await service.get_event_iocs(
            event_id,
            enforce_warninglist=enforce_warninglist,
            to_ids_only=to_ids,
        )
        return MISPEventIOCs(
            event_id=event_id,
            event_info=event['info'],
            iocs_by_type=iocs,
        )
    finally:
        await service.close()


@router.get("/supported-types")
async def get_supported_ioc_types(
    _: Annotated[User, Depends(get_current_user)],
):
    """Get list of supported IOC types for rule generation."""
    return {"types": SigmaRuleGenerator.get_supported_types()}


@router.post("/import-rule", response_model=MISPImportResponse)
async def import_rule(
    request: MISPImportRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission_dep("manage_rules"))],
):
    """Import IOCs from MISP as a Sigma rule."""
    config = await get_misp_config(db)
    if not config:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MISP is not configured",
        )

    service = await get_misp_service(db)

    try:
        # Get event details
        event = await service.get_event(request.event_id)

        # Build IOC list
        iocs = [{'value': v} for v in request.ioc_values]

        # Generate Sigma rule
        generator = SigmaRuleGenerator()
        result = generator.generate_rule(
            event_info=event,
            ioc_type=request.ioc_type,
            iocs=iocs,
            misp_url=config.instance_url,
        )

        # Convert rule dict to YAML
        rule_yaml = yaml.dump(result['rule'], default_flow_style=False, sort_keys=False)

        # Create rule in database
        rule = Rule(
            title=result['rule']['title'],
            description=result['rule']['description'],
            yaml_content=rule_yaml,
            severity=result['rule']['level'],
            status=RuleStatus.UNDEPLOYED,
            index_pattern_id=request.index_pattern_id,
            created_by=current_user.id,
            source=RuleSource.MISP,
        )
        db.add(rule)
        await db.flush()

        # Create initial version
        version = RuleVersion(
            rule_id=rule.id,
            version_number=1,
            yaml_content=rule_yaml,
            changed_by=current_user.id,
            change_reason="Imported from MISP",
            created_at=datetime.now(UTC),
        )
        db.add(version)

        # Create MISP import tracking record
        event_date = None
        if event.get('date'):
            try:
                event_date = datetime.fromisoformat(event['date'])
            except ValueError:
                pass  # Skip if date format is invalid

        misp_import = MISPImportedRule(
            rule_id=rule.id,
            misp_url=config.instance_url,
            misp_event_id=request.event_id,
            misp_event_uuid=event.get('uuid'),
            misp_event_info=event.get('info'),
            misp_event_date=event_date,
            misp_event_threat_level=event.get('threat_level'),
            ioc_type=request.ioc_type,
            ioc_count=len(request.ioc_values),
            ioc_values={'values': request.ioc_values},
        )
        db.add(misp_import)

        # Update ATT&CK mappings from rule tags
        tags = result['rule'].get('tags', [])
        try:
            await update_rule_attack_mappings(db, str(rule.id), tags)
        except Exception:
            pass  # Don't fail import if ATT&CK mapping fails

        await db.commit()
        await db.refresh(rule)

        return MISPImportResponse(
            success=True,
            rule_id=str(rule.id),
            title=rule.title,
            message="Rule imported successfully. Review field mappings and deploy when ready.",
        )

    finally:
        await service.close()


@router.get("/rules/{rule_id}/misp-info", response_model=MISPImportedRuleInfo | None)
async def get_rule_misp_info(
    rule_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    """Get MISP origin information for a rule."""
    result = await db.execute(
        select(MISPImportedRule).where(MISPImportedRule.rule_id == rule_id)
    )
    misp_import = result.scalar_one_or_none()

    if not misp_import:
        return None

    return MISPImportedRuleInfo(
        misp_url=misp_import.misp_url,
        misp_event_id=misp_import.misp_event_id,
        misp_event_uuid=misp_import.misp_event_uuid,
        misp_event_info=misp_import.misp_event_info,
        misp_event_date=misp_import.misp_event_date,
        misp_event_threat_level=misp_import.misp_event_threat_level,
        ioc_type=misp_import.ioc_type,
        ioc_count=misp_import.ioc_count,
        imported_at=misp_import.imported_at,
        last_checked_at=misp_import.last_checked_at,
        has_updates=False,  # TODO: Implement update checking
    )
