"""Well-known identifiers for the single default organization.

Mirrors VectorFlow's ``DEFAULT_ORG_ID`` sentinel: OSS / self-hosted deployments
run as one organization and every tenant row backfills to this org, so
single-tenant behaviour is unchanged. Multi-tenant (MSSP) deployments create
real Organization rows with their own ids/slugs on signup; this constant is only
the single-tenant sentinel and the migration backfill target.
"""

import uuid

# Fixed UUID for the default org (stable across installs so the backfill and any
# code that needs "the default org" agree without a lookup).
DEFAULT_ORG_ID = uuid.UUID("00000000-0000-0000-0000-000000000001")
DEFAULT_ORG_SLUG = "default"

# Org slug grammar shared with host→org resolution and enrollment: lowercase
# letters/digits/hyphens, 3–31 chars, starts with a letter.
ORG_SLUG_PATTERN = r"^[a-z][a-z0-9-]{2,30}$"
