"""
Export API for rules and configuration backup.
"""

import io
import json
import zipfile
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_admin
from app.db.session import get_db
from app.models.index_pattern import IndexPattern
from app.models.rule import Rule
from app.models.setting import Setting
from app.models.user import User

router = APIRouter(prefix="/export", tags=["export"])


class BulkExportRequest(BaseModel):
    rule_ids: list[str]


def sanitize_filename(title: str) -> str:
    """Sanitize title for use in filename."""
    return "".join(c if c.isalnum() or c in "-_" else "_" for c in title)


@router.get("/rules/{rule_id}")
async def export_single_rule(
    rule_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    """Export a single rule as YAML file."""
    rule = await db.get(Rule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    safe_title = sanitize_filename(rule.title)
    filename = f"{safe_title}.yml"

    return Response(
        content=rule.yaml_content,
        media_type="application/x-yaml",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/rules/bulk")
async def export_bulk_rules(
    data: BulkExportRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    """Export multiple rules as ZIP file."""
    result = await db.execute(select(Rule).where(Rule.id.in_(data.rule_ids)))
    rules = result.scalars().all()

    if not rules:
        raise HTTPException(status_code=404, detail="No rules found for the given IDs")

    # Create ZIP in memory
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for rule in rules:
            safe_title = sanitize_filename(rule.title)
            zf.writestr(f"{safe_title}.yml", rule.yaml_content)

    zip_buffer.seek(0)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")

    return StreamingResponse(
        zip_buffer,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="chad-rules-{timestamp}.zip"'
        },
    )


@router.get("/rules")
async def export_all_rules(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    """Export all rules as ZIP file."""
    result = await db.execute(select(Rule))
    rules = result.scalars().all()

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for rule in rules:
            safe_title = sanitize_filename(rule.title)
            zf.writestr(f"{safe_title}.yml", rule.yaml_content)

    zip_buffer.seek(0)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")

    return StreamingResponse(
        zip_buffer,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="chad-rules-all-{timestamp}.zip"'
        },
    )


@router.get("/config")
async def export_config(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_admin)],
):
    """Export configuration backup as JSON (no secrets)."""
    # Get index patterns (without auth tokens)
    patterns_result = await db.execute(select(IndexPattern))
    index_patterns = [
        {
            "name": p.name,
            "pattern": p.pattern,
            "percolator_index": p.percolator_index,
            "description": p.description,
        }
        for p in patterns_result.scalars()
    ]

    # Get settings (filter out sensitive ones)
    settings_result = await db.execute(select(Setting))
    settings = {
        s.key: s.value
        for s in settings_result.scalars()
        if not s.key.startswith("secret_")
        and not s.key.endswith("_token")
        and "password" not in s.key.lower()
        and s.key != "opensearch"  # Exclude OpenSearch config (contains credentials)
    }

    config = {
        "exported_at": datetime.now().isoformat(),
        "version": "1.0",
        "index_patterns": index_patterns,
        "settings": settings,
    }

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")

    return Response(
        content=json.dumps(config, indent=2),
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="chad-config-{timestamp}.json"'
        },
    )
