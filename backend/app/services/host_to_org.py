"""Resolve the organization an HTTP request belongs to from its Host header.

Wildcard subdomain layout ``<orgSlug>.chad.example.com``: the first DNS label is
the tenant slug. OSS deployments use single-label hosts (``localhost``), bare
IPs, or a custom domain without an org prefix — those fall back to the default
org, so OSS users see no behaviour change. Mirrors VectorFlow's host_to_org.
"""

from __future__ import annotations

import re
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.org_constants import DEFAULT_ORG_ID, ORG_SLUG_PATTERN
from app.models.organization import Organization

_SLUG_RE = re.compile(ORG_SLUG_PATTERN)


def normalize_host(host: str) -> str:
    """Strip port + IPv6 brackets from a Host value."""
    h = host.strip()
    if h.startswith("["):
        close = h.find("]")
        if close > 0:
            return h[1:close]
    colon = h.rfind(":")
    if colon > 0:
        h = h[:colon]
    return h


def extract_slug_from_host(normalized_host: str) -> str | None:
    """Candidate org slug = first label, when the host has ≥2 labels and the
    label is a valid slug. ≥2 labels so ``localhost`` / bare IPs never match."""
    labels = normalized_host.split(".")
    if len(labels) < 2:
        return None
    candidate = labels[0].lower()
    return candidate if _SLUG_RE.match(candidate) else None


async def resolve_org_id_from_host(db: AsyncSession, host: str | None) -> uuid.UUID:
    """Map a raw Host value → org id, falling back to the default org.

    Fails open to the default org for OSS hosts, missing hosts, or unknown
    slugs. Cross-org access from a spoofed slug is prevented by org scoping +
    per-org auth, not by this lookup.
    """
    if not host:
        return DEFAULT_ORG_ID
    slug = extract_slug_from_host(normalize_host(host))
    if not slug:
        return DEFAULT_ORG_ID
    try:
        org_id = (
            await db.execute(select(Organization.id).where(Organization.slug == slug))
        ).scalar_one_or_none()
        return org_id or DEFAULT_ORG_ID
    except Exception:
        # DB unreachable (build phase, migration in progress) — preserve OSS.
        return DEFAULT_ORG_ID
