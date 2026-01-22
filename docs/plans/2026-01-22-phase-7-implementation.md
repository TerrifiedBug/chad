# CHAD Phase 7 Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement Phase 7 features including rate limiting, bulk operations, activity panel with comments, export/backup, audit to OpenSearch, role permissions, rules list redesign, and quality-of-life improvements.

**Architecture:** PostgreSQL for rate limiting (login_attempts), rule comments, and role permissions. OpenSearch dual-write for audit logs. Frontend uses React with shadcn/ui components. Tree/table view toggle for rules list with localStorage persistence.

**Tech Stack:** FastAPI, SQLAlchemy, PostgreSQL, OpenSearch, React, shadcn/ui, Tailwind CSS, ruamel.yaml, diff-match-patch

---

## Phase Overview

Phase 7 consists of 12 features organized into 4 groups:

**Group A - Security & Permissions (Tasks 1-8):**
1. Rate Limiting - Login attempt tracking and account lockout
2. Role Permissions - Configurable permissions per role

**Group B - Rules Management (Tasks 9-20):**
3. Bulk Operations - Multi-select enable/disable/delete/deploy/undeploy
4. Rules List Redesign - Tree/table view toggle with filters
5. Activity Panel - Version history with diff view
6. Rule Comments - Comments in activity timeline

**Group C - Data Export & Audit (Tasks 21-26):**
7. Export/Backup - Single rule, bulk, config export
8. Audit to OpenSearch - Dual-write toggle

**Group D - Quality of Life (Tasks 27-32):**
9. OIDC Role Management - Edit roles when mapping disabled
10. YAML Auto-formatting - Format button with ruamel.yaml
11. Dialog Standards - Replace browser confirm() everywhere
12. Audit Logging Gaps - Add missing audit events

---

## Group A: Security & Permissions

### Task 1: Login Attempts Model

**Files:**
- Create: `backend/app/models/login_attempt.py`
- Modify: `backend/app/models/__init__.py`

**Step 1: Create the login attempt model**

```python
# backend/app/models/login_attempt.py
"""
Login attempt tracking for rate limiting.

Stores failed login attempts per account (email) for lockout logic.
"""

from datetime import datetime
from sqlalchemy import String, DateTime, Integer
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class LoginAttempt(Base):
    """Track failed login attempts for rate limiting."""

    __tablename__ = "login_attempts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    email: Mapped[str] = mapped_column(String(255), index=True)
    ip_address: Mapped[str] = mapped_column(String(45))  # IPv6 max length
    attempted_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    def __repr__(self) -> str:
        return f"<LoginAttempt {self.email} at {self.attempted_at}>"
```

**Step 2: Update models __init__.py**

Add to `backend/app/models/__init__.py`:
```python
from app.models.login_attempt import LoginAttempt
```

**Step 3: Commit**

```bash
git add backend/app/models/login_attempt.py backend/app/models/__init__.py
git commit -m "feat(models): add LoginAttempt model for rate limiting"
```

---

### Task 2: Login Attempts Migration

**Files:**
- Create: `backend/alembic/versions/XXXX_add_login_attempts_table.py`

**Step 1: Generate migration**

```bash
docker compose -f docker-compose.dev.yml run --rm backend alembic revision --autogenerate -m "add_login_attempts_table"
```

**Step 2: Review and adjust migration if needed**

The migration should create:
- `login_attempts` table with id, email, ip_address, attempted_at
- Index on email column

**Step 3: Run migration**

```bash
docker compose -f docker-compose.dev.yml run --rm backend alembic upgrade head
```

**Step 4: Commit**

```bash
git add backend/alembic/versions/
git commit -m "feat(db): add login_attempts migration"
```

---

### Task 3: Rate Limiting Settings

**Files:**
- Modify: `backend/app/services/settings.py`

**Step 1: Add rate limiting settings with defaults**

Add to the settings service (or create if not exists):

```python
# Add these default settings
RATE_LIMIT_DEFAULTS = {
    "rate_limit_enabled": True,
    "rate_limit_max_attempts": 5,
    "rate_limit_lockout_minutes": 15,
}
```

**Step 2: Commit**

```bash
git add backend/app/services/settings.py
git commit -m "feat(settings): add rate limiting configuration defaults"
```

---

### Task 4: Rate Limiting Service

**Files:**
- Create: `backend/app/services/rate_limit.py`

**Step 1: Create rate limiting service**

```python
# backend/app/services/rate_limit.py
"""
Rate limiting service for login protection.

Tracks failed login attempts per account and enforces lockout policy.
"""

from datetime import datetime, timedelta
from sqlalchemy import select, func, delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.login_attempt import LoginAttempt
from app.services.settings import get_setting


async def get_rate_limit_settings(db: AsyncSession) -> dict:
    """Get rate limiting configuration from settings."""
    return {
        "enabled": await get_setting(db, "rate_limit_enabled", True),
        "max_attempts": await get_setting(db, "rate_limit_max_attempts", 5),
        "lockout_minutes": await get_setting(db, "rate_limit_lockout_minutes", 15),
    }


async def record_failed_attempt(
    db: AsyncSession,
    email: str,
    ip_address: str,
) -> None:
    """Record a failed login attempt."""
    attempt = LoginAttempt(
        email=email.lower(),
        ip_address=ip_address,
        attempted_at=datetime.utcnow(),
    )
    db.add(attempt)
    await db.commit()


async def get_failed_attempt_count(
    db: AsyncSession,
    email: str,
    window_minutes: int,
) -> int:
    """Count failed attempts for an account within the time window."""
    cutoff = datetime.utcnow() - timedelta(minutes=window_minutes)
    result = await db.execute(
        select(func.count()).select_from(LoginAttempt).where(
            LoginAttempt.email == email.lower(),
            LoginAttempt.attempted_at >= cutoff,
        )
    )
    return result.scalar() or 0


async def is_account_locked(db: AsyncSession, email: str) -> tuple[bool, int]:
    """
    Check if account is locked due to too many failed attempts.

    Returns:
        (is_locked, remaining_minutes)
    """
    settings = await get_rate_limit_settings(db)

    if not settings["enabled"]:
        return False, 0

    count = await get_failed_attempt_count(
        db, email, settings["lockout_minutes"]
    )

    if count >= settings["max_attempts"]:
        return True, settings["lockout_minutes"]

    return False, 0


async def clear_failed_attempts(db: AsyncSession, email: str) -> None:
    """Clear failed attempts for an account after successful login."""
    await db.execute(
        delete(LoginAttempt).where(LoginAttempt.email == email.lower())
    )
    await db.commit()


async def cleanup_old_attempts(db: AsyncSession, older_than_minutes: int = 60) -> int:
    """Remove login attempts older than specified minutes. Returns count deleted."""
    cutoff = datetime.utcnow() - timedelta(minutes=older_than_minutes)
    result = await db.execute(
        delete(LoginAttempt).where(LoginAttempt.attempted_at < cutoff)
    )
    await db.commit()
    return result.rowcount
```

**Step 2: Commit**

```bash
git add backend/app/services/rate_limit.py
git commit -m "feat(services): add rate limiting service"
```

---

### Task 5: Integrate Rate Limiting into Auth

**Files:**
- Modify: `backend/app/api/auth.py`

**Step 1: Import rate limiting functions**

Add imports:
```python
from app.services.rate_limit import (
    is_account_locked,
    record_failed_attempt,
    clear_failed_attempts,
)
from app.services.audit import audit_log
```

**Step 2: Update login endpoint**

Modify the login endpoint to:
1. Check if account is locked before attempting auth
2. Record failed attempts
3. Clear attempts on successful login
4. Audit all events

```python
@router.post("/login")
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    request: Request = None,
    db: AsyncSession = Depends(get_db),
):
    email = form_data.username.lower()
    ip_address = request.client.host if request else "unknown"

    # Check if account is locked
    is_locked, lockout_minutes = await is_account_locked(db, email)
    if is_locked:
        # Audit the attempt on locked account
        await audit_log(
            db, None, "auth.lockout_login_attempt", "user", None,
            {"email": email, "ip_address": ip_address}
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Account locked due to too many failed attempts. Try again in {lockout_minutes} minutes.",
        )

    # Attempt authentication
    user = await authenticate_user(db, email, form_data.password)

    if not user:
        # Record failed attempt
        await record_failed_attempt(db, email, ip_address)

        # Audit failed login
        await audit_log(
            db, None, "auth.login_failed", "user", None,
            {"email": email, "ip_address": ip_address, "reason": "invalid_credentials"}
        )

        # Check if this attempt triggered a lockout
        is_locked, _ = await is_account_locked(db, email)
        if is_locked:
            await audit_log(
                db, None, "auth.lockout", "user", None,
                {"email": email, "ip_address": ip_address}
            )

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    # Successful login - clear failed attempts
    await clear_failed_attempts(db, email)

    # ... rest of login logic (create token, etc.)
```

**Step 3: Commit**

```bash
git add backend/app/api/auth.py
git commit -m "feat(auth): integrate rate limiting into login flow"
```

---

### Task 6: Rate Limiting Settings UI

**Files:**
- Modify: `frontend/src/pages/Settings.tsx`

**Step 1: Add rate limiting settings section**

Add state and UI for rate limiting settings:

```typescript
// Add state
const [rateLimitEnabled, setRateLimitEnabled] = useState(true)
const [rateLimitMaxAttempts, setRateLimitMaxAttempts] = useState(5)
const [rateLimitLockoutMinutes, setRateLimitLockoutMinutes] = useState(15)

// Add to settings load
const loadSettings = async () => {
  // ... existing code
  setRateLimitEnabled(settings.rate_limit_enabled ?? true)
  setRateLimitMaxAttempts(settings.rate_limit_max_attempts ?? 5)
  setRateLimitLockoutMinutes(settings.rate_limit_lockout_minutes ?? 15)
}

// Add UI in a "Security" tab
<TabsContent value="security" className="space-y-6">
  <Card>
    <CardHeader>
      <CardTitle>Rate Limiting</CardTitle>
      <CardDescription>
        Protect against brute force attacks by limiting failed login attempts
      </CardDescription>
    </CardHeader>
    <CardContent className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <Label>Enable Rate Limiting</Label>
          <p className="text-sm text-muted-foreground">
            Lock accounts after too many failed login attempts
          </p>
        </div>
        <Switch
          checked={rateLimitEnabled}
          onCheckedChange={setRateLimitEnabled}
        />
      </div>

      {rateLimitEnabled && (
        <>
          <div className="space-y-2">
            <Label>Max Failed Attempts</Label>
            <Input
              type="number"
              min={1}
              max={20}
              value={rateLimitMaxAttempts}
              onChange={(e) => setRateLimitMaxAttempts(parseInt(e.target.value))}
            />
            <p className="text-xs text-muted-foreground">
              Number of failed attempts before account lockout
            </p>
          </div>

          <div className="space-y-2">
            <Label>Lockout Duration (minutes)</Label>
            <Input
              type="number"
              min={1}
              max={1440}
              value={rateLimitLockoutMinutes}
              onChange={(e) => setRateLimitLockoutMinutes(parseInt(e.target.value))}
            />
            <p className="text-xs text-muted-foreground">
              How long to lock the account after max attempts
            </p>
          </div>
        </>
      )}
    </CardContent>
  </Card>
</TabsContent>
```

**Step 2: Commit**

```bash
git add frontend/src/pages/Settings.tsx
git commit -m "feat(frontend): add rate limiting settings UI"
```

---

### Task 7: Role Permissions Model

**Files:**
- Create: `backend/app/models/role_permission.py`
- Modify: `backend/app/models/__init__.py`

**Step 1: Create role permissions model**

```python
# backend/app/models/role_permission.py
"""
Role permissions configuration.

Stores customizable permissions for each role (admin, analyst, viewer).
"""

from sqlalchemy import String, Boolean
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class RolePermission(Base):
    """Configurable permission for a role."""

    __tablename__ = "role_permissions"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    role: Mapped[str] = mapped_column(String(50), index=True)  # admin, analyst, viewer
    permission: Mapped[str] = mapped_column(String(100))  # permission name
    granted: Mapped[bool] = mapped_column(Boolean, default=False)

    __table_args__ = (
        # Unique constraint on role + permission
        {"sqlite_autoincrement": True},
    )


# Default permissions by role
DEFAULT_ROLE_PERMISSIONS = {
    "admin": {
        "manage_users": True,
        "manage_rules": True,
        "deploy_rules": True,
        "manage_settings": True,
        "manage_api_keys": True,
        "view_audit": True,
        "manage_sigmahq": True,
    },
    "analyst": {
        "manage_users": False,
        "manage_rules": True,
        "deploy_rules": True,
        "manage_settings": False,
        "manage_api_keys": True,
        "view_audit": True,
        "manage_sigmahq": True,
    },
    "viewer": {
        "manage_users": False,
        "manage_rules": False,
        "deploy_rules": False,
        "manage_settings": False,
        "manage_api_keys": False,
        "view_audit": False,
        "manage_sigmahq": False,
    },
}

PERMISSION_DESCRIPTIONS = {
    "manage_users": "Create, edit, and delete users",
    "manage_rules": "Create, edit, and delete detection rules",
    "deploy_rules": "Deploy and undeploy rules to OpenSearch",
    "manage_settings": "Modify system settings and webhooks",
    "manage_api_keys": "Create and revoke API keys",
    "view_audit": "Access the audit log viewer",
    "manage_sigmahq": "Sync and import SigmaHQ rules",
}
```

**Step 2: Update models __init__.py**

Add to `backend/app/models/__init__.py`:
```python
from app.models.role_permission import RolePermission, DEFAULT_ROLE_PERMISSIONS
```

**Step 3: Commit**

```bash
git add backend/app/models/role_permission.py backend/app/models/__init__.py
git commit -m "feat(models): add RolePermission model"
```

---

### Task 8: Role Permissions API & Service

**Files:**
- Create: `backend/app/services/permissions.py`
- Create: `backend/app/api/permissions.py`
- Modify: `backend/app/main.py`

**Step 1: Create permissions service**

```python
# backend/app/services/permissions.py
"""
Permission checking service.

Handles role-based permission checks and permission management.
"""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.role_permission import RolePermission, DEFAULT_ROLE_PERMISSIONS
from app.models.user import User


async def get_role_permissions(db: AsyncSession, role: str) -> dict[str, bool]:
    """Get all permissions for a role, with defaults applied."""
    # Start with defaults
    defaults = DEFAULT_ROLE_PERMISSIONS.get(role, {})
    permissions = dict(defaults)

    # Override with any customizations from database
    result = await db.execute(
        select(RolePermission).where(RolePermission.role == role)
    )
    for perm in result.scalars():
        permissions[perm.permission] = perm.granted

    return permissions


async def has_permission(db: AsyncSession, user: User, permission: str) -> bool:
    """Check if a user has a specific permission."""
    # Admin always has all permissions
    if user.role == "admin":
        return True

    permissions = await get_role_permissions(db, user.role)
    return permissions.get(permission, False)


async def set_role_permission(
    db: AsyncSession,
    role: str,
    permission: str,
    granted: bool,
) -> None:
    """Set a permission for a role."""
    # Don't allow modifying admin permissions
    if role == "admin":
        return

    result = await db.execute(
        select(RolePermission).where(
            RolePermission.role == role,
            RolePermission.permission == permission,
        )
    )
    existing = result.scalar_one_or_none()

    if existing:
        existing.granted = granted
    else:
        db.add(RolePermission(role=role, permission=permission, granted=granted))

    await db.commit()


async def get_all_role_permissions(db: AsyncSession) -> dict[str, dict[str, bool]]:
    """Get permissions for all roles."""
    return {
        "admin": await get_role_permissions(db, "admin"),
        "analyst": await get_role_permissions(db, "analyst"),
        "viewer": await get_role_permissions(db, "viewer"),
    }
```

**Step 2: Create permissions API**

```python
# backend/app/api/permissions.py
"""
Role permissions API endpoints.
"""

from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_admin
from app.db.session import get_db
from app.models.user import User
from app.models.role_permission import PERMISSION_DESCRIPTIONS
from app.services.permissions import get_all_role_permissions, set_role_permission
from app.services.audit import audit_log

router = APIRouter(prefix="/permissions", tags=["permissions"])


class PermissionUpdate(BaseModel):
    role: str
    permission: str
    granted: bool


class PermissionsResponse(BaseModel):
    roles: dict[str, dict[str, bool]]
    descriptions: dict[str, str]


@router.get("", response_model=PermissionsResponse)
async def get_permissions(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_admin)],
):
    """Get all role permissions."""
    roles = await get_all_role_permissions(db)
    return PermissionsResponse(roles=roles, descriptions=PERMISSION_DESCRIPTIONS)


@router.put("")
async def update_permission(
    data: PermissionUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_admin)],
):
    """Update a role permission."""
    if data.role == "admin":
        return {"error": "Cannot modify admin permissions"}

    await set_role_permission(db, data.role, data.permission, data.granted)
    await audit_log(
        db, current_user.id, "permission.update", "role_permission", None,
        {"role": data.role, "permission": data.permission, "granted": data.granted}
    )

    return {"success": True}
```

**Step 3: Register router in main.py**

Add to `backend/app/main.py`:
```python
from app.api.permissions import router as permissions_router
app.include_router(permissions_router, prefix="/api")
```

**Step 4: Commit**

```bash
git add backend/app/services/permissions.py backend/app/api/permissions.py backend/app/main.py
git commit -m "feat(api): add role permissions API and service"
```

---

## Group B: Rules Management

### Task 9: Bulk Operations API

**Files:**
- Modify: `backend/app/api/rules.py`
- Create: `backend/app/schemas/bulk.py`

**Step 1: Create bulk operation schemas**

```python
# backend/app/schemas/bulk.py
"""Schemas for bulk operations."""

from pydantic import BaseModel


class BulkOperationRequest(BaseModel):
    rule_ids: list[str]


class BulkOperationResult(BaseModel):
    success: list[str]
    failed: list[dict]  # {"id": str, "error": str}
```

**Step 2: Add bulk endpoints to rules API**

Add to `backend/app/api/rules.py`:

```python
from app.schemas.bulk import BulkOperationRequest, BulkOperationResult

@router.post("/bulk/enable", response_model=BulkOperationResult)
async def bulk_enable_rules(
    data: BulkOperationRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    """Enable multiple rules."""
    success = []
    failed = []

    for rule_id in data.rule_ids:
        try:
            rule = await db.get(Rule, rule_id)
            if rule:
                rule.status = "enabled"
                success.append(rule_id)
            else:
                failed.append({"id": rule_id, "error": "Rule not found"})
        except Exception as e:
            failed.append({"id": rule_id, "error": str(e)})

    await db.commit()
    await audit_log(db, current_user.id, "rule.bulk_enable", "rule", None,
                    {"count": len(success), "rule_ids": success})

    return BulkOperationResult(success=success, failed=failed)


@router.post("/bulk/disable", response_model=BulkOperationResult)
async def bulk_disable_rules(
    data: BulkOperationRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    """Disable multiple rules."""
    success = []
    failed = []

    for rule_id in data.rule_ids:
        try:
            rule = await db.get(Rule, rule_id)
            if rule:
                rule.status = "disabled"
                success.append(rule_id)
            else:
                failed.append({"id": rule_id, "error": "Rule not found"})
        except Exception as e:
            failed.append({"id": rule_id, "error": str(e)})

    await db.commit()
    await audit_log(db, current_user.id, "rule.bulk_disable", "rule", None,
                    {"count": len(success), "rule_ids": success})

    return BulkOperationResult(success=success, failed=failed)


@router.post("/bulk/delete", response_model=BulkOperationResult)
async def bulk_delete_rules(
    data: BulkOperationRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    """Delete multiple rules."""
    success = []
    failed = []

    for rule_id in data.rule_ids:
        try:
            rule = await db.get(Rule, rule_id)
            if rule:
                await db.delete(rule)
                success.append(rule_id)
            else:
                failed.append({"id": rule_id, "error": "Rule not found"})
        except Exception as e:
            failed.append({"id": rule_id, "error": str(e)})

    await db.commit()
    await audit_log(db, current_user.id, "rule.bulk_delete", "rule", None,
                    {"count": len(success), "rule_ids": success})

    return BulkOperationResult(success=success, failed=failed)


@router.post("/bulk/deploy", response_model=BulkOperationResult)
async def bulk_deploy_rules(
    data: BulkOperationRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    os_client: OpenSearch = Depends(get_opensearch_client),
):
    """Deploy multiple rules."""
    success = []
    failed = []

    for rule_id in data.rule_ids:
        try:
            # Reuse existing deploy logic
            result = await deploy_rule_internal(db, os_client, rule_id)
            if result:
                success.append(rule_id)
            else:
                failed.append({"id": rule_id, "error": "Deploy failed"})
        except Exception as e:
            failed.append({"id": rule_id, "error": str(e)})

    await audit_log(db, current_user.id, "rule.bulk_deploy", "rule", None,
                    {"count": len(success), "rule_ids": success})

    return BulkOperationResult(success=success, failed=failed)


@router.post("/bulk/undeploy", response_model=BulkOperationResult)
async def bulk_undeploy_rules(
    data: BulkOperationRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    os_client: OpenSearch = Depends(get_opensearch_client),
):
    """Undeploy multiple rules."""
    success = []
    failed = []

    for rule_id in data.rule_ids:
        try:
            # Reuse existing undeploy logic
            result = await undeploy_rule_internal(db, os_client, rule_id)
            if result:
                success.append(rule_id)
            else:
                failed.append({"id": rule_id, "error": "Undeploy failed"})
        except Exception as e:
            failed.append({"id": rule_id, "error": str(e)})

    await audit_log(db, current_user.id, "rule.bulk_undeploy", "rule", None,
                    {"count": len(success), "rule_ids": success})

    return BulkOperationResult(success=success, failed=failed)
```

**Step 3: Commit**

```bash
git add backend/app/api/rules.py backend/app/schemas/bulk.py
git commit -m "feat(api): add bulk operations endpoints for rules"
```

---

### Task 10: Bulk Operations Frontend API

**Files:**
- Modify: `frontend/src/lib/api.ts`

**Step 1: Add bulk operations API functions**

```typescript
// Add to rulesApi object
bulkEnable: (ruleIds: string[]) =>
  api.post<{ success: string[]; failed: { id: string; error: string }[] }>(
    '/rules/bulk/enable',
    { rule_ids: ruleIds }
  ),
bulkDisable: (ruleIds: string[]) =>
  api.post<{ success: string[]; failed: { id: string; error: string }[] }>(
    '/rules/bulk/disable',
    { rule_ids: ruleIds }
  ),
bulkDelete: (ruleIds: string[]) =>
  api.post<{ success: string[]; failed: { id: string; error: string }[] }>(
    '/rules/bulk/delete',
    { rule_ids: ruleIds }
  ),
bulkDeploy: (ruleIds: string[]) =>
  api.post<{ success: string[]; failed: { id: string; error: string }[] }>(
    '/rules/bulk/deploy',
    { rule_ids: ruleIds }
  ),
bulkUndeploy: (ruleIds: string[]) =>
  api.post<{ success: string[]; failed: { id: string; error: string }[] }>(
    '/rules/bulk/undeploy',
    { rule_ids: ruleIds }
  ),
```

**Step 2: Commit**

```bash
git add frontend/src/lib/api.ts
git commit -m "feat(frontend): add bulk operations API functions"
```

---

### Task 11: Rules List Component - Selection State

**Files:**
- Modify: `frontend/src/pages/Rules.tsx`

**Step 1: Add selection state and handlers**

```typescript
// Add state for selection
const [selectedRules, setSelectedRules] = useState<Set<string>>(new Set())
const [lastSelectedIndex, setLastSelectedIndex] = useState<number | null>(null)

// Toggle single selection
const toggleRuleSelection = (ruleId: string, index: number, shiftKey: boolean) => {
  setSelectedRules(prev => {
    const newSet = new Set(prev)

    if (shiftKey && lastSelectedIndex !== null) {
      // Shift+click: select range
      const start = Math.min(lastSelectedIndex, index)
      const end = Math.max(lastSelectedIndex, index)
      for (let i = start; i <= end; i++) {
        newSet.add(rules[i].id)
      }
    } else {
      // Regular click: toggle single
      if (newSet.has(ruleId)) {
        newSet.delete(ruleId)
      } else {
        newSet.add(ruleId)
      }
    }

    return newSet
  })
  setLastSelectedIndex(index)
}

// Select all (on current page/filtered)
const selectAll = () => {
  if (selectedRules.size === rules.length) {
    setSelectedRules(new Set())
  } else {
    setSelectedRules(new Set(rules.map(r => r.id)))
  }
}

// Clear selection
const clearSelection = () => {
  setSelectedRules(new Set())
  setLastSelectedIndex(null)
}
```

**Step 2: Commit**

```bash
git add frontend/src/pages/Rules.tsx
git commit -m "feat(frontend): add rule selection state with shift+click support"
```

---

### Task 12: Rules List Component - Bulk Action Bar

**Files:**
- Modify: `frontend/src/pages/Rules.tsx`

**Step 1: Add bulk action bar component**

```typescript
// Add bulk action handlers
const [isBulkOperating, setIsBulkOperating] = useState(false)

const handleBulkAction = async (action: 'enable' | 'disable' | 'deploy' | 'undeploy' | 'delete') => {
  if (selectedRules.size === 0) return

  if (action === 'delete') {
    // Show confirmation dialog
    setShowBulkDeleteConfirm(true)
    return
  }

  setIsBulkOperating(true)
  try {
    const ruleIds = Array.from(selectedRules)
    let result

    switch (action) {
      case 'enable':
        result = await rulesApi.bulkEnable(ruleIds)
        break
      case 'disable':
        result = await rulesApi.bulkDisable(ruleIds)
        break
      case 'deploy':
        result = await rulesApi.bulkDeploy(ruleIds)
        break
      case 'undeploy':
        result = await rulesApi.bulkUndeploy(ruleIds)
        break
    }

    // Show result toast
    if (result.failed.length > 0) {
      setError(`${result.success.length} succeeded, ${result.failed.length} failed`)
    }

    clearSelection()
    loadRules()
  } catch (err) {
    setError(err instanceof Error ? err.message : 'Bulk operation failed')
  } finally {
    setIsBulkOperating(false)
  }
}

// Bulk action bar JSX (shown when items selected)
{selectedRules.size > 0 && (
  <div className="fixed bottom-6 left-1/2 -translate-x-1/2 bg-background border rounded-lg shadow-lg p-4 flex items-center gap-4 z-50">
    <span className="text-sm font-medium">
      {selectedRules.size} rule{selectedRules.size > 1 ? 's' : ''} selected
    </span>
    <div className="flex gap-2">
      <Button size="sm" variant="outline" onClick={() => handleBulkAction('enable')} disabled={isBulkOperating}>
        Enable
      </Button>
      <Button size="sm" variant="outline" onClick={() => handleBulkAction('disable')} disabled={isBulkOperating}>
        Disable
      </Button>
      <Button size="sm" variant="outline" onClick={() => handleBulkAction('deploy')} disabled={isBulkOperating}>
        Deploy
      </Button>
      <Button size="sm" variant="outline" onClick={() => handleBulkAction('undeploy')} disabled={isBulkOperating}>
        Undeploy
      </Button>
      <Button size="sm" variant="destructive" onClick={() => handleBulkAction('delete')} disabled={isBulkOperating}>
        Delete
      </Button>
    </div>
    <Button size="sm" variant="ghost" onClick={clearSelection}>
      Cancel
    </Button>
  </div>
)}
```

**Step 2: Commit**

```bash
git add frontend/src/pages/Rules.tsx
git commit -m "feat(frontend): add bulk action bar for rules"
```

---

### Task 13: Rules List - Table View with Checkboxes

**Files:**
- Modify: `frontend/src/pages/Rules.tsx`

**Step 1: Add checkbox column to table**

Update the table to include checkboxes:

```typescript
<Table>
  <TableHeader>
    <TableRow>
      <TableHead className="w-12">
        <Checkbox
          checked={selectedRules.size === rules.length && rules.length > 0}
          onCheckedChange={selectAll}
        />
      </TableHead>
      <TableHead>Title</TableHead>
      <TableHead>Index Pattern</TableHead>
      <TableHead>Severity</TableHead>
      <TableHead>Status</TableHead>
      <TableHead>Sigma Status</TableHead>
      <TableHead>Deployed</TableHead>
      <TableHead>Last Edited</TableHead>
      <TableHead>Edited By</TableHead>
      <TableHead>Actions</TableHead>
    </TableRow>
  </TableHeader>
  <TableBody>
    {rules.map((rule, index) => (
      <TableRow key={rule.id} className={selectedRules.has(rule.id) ? 'bg-muted/50' : ''}>
        <TableCell>
          <Checkbox
            checked={selectedRules.has(rule.id)}
            onCheckedChange={(checked) => {
              // Get shift key from last event
              toggleRuleSelection(rule.id, index, false)
            }}
            onClick={(e) => {
              e.stopPropagation()
              toggleRuleSelection(rule.id, index, e.shiftKey)
            }}
          />
        </TableCell>
        <TableCell>{rule.title}</TableCell>
        {/* ... other columns */}
      </TableRow>
    ))}
  </TableBody>
</Table>
```

**Step 2: Commit**

```bash
git add frontend/src/pages/Rules.tsx
git commit -m "feat(frontend): add checkbox selection to rules table"
```

---

### Task 14: Rules List - View Toggle (Tree/Table)

**Files:**
- Modify: `frontend/src/pages/Rules.tsx`

**Step 1: Add view toggle state with localStorage persistence**

```typescript
// View state
const [viewMode, setViewMode] = useState<'tree' | 'table'>(() => {
  return (localStorage.getItem('rules-view-mode') as 'tree' | 'table') || 'table'
})

// Persist view mode
useEffect(() => {
  localStorage.setItem('rules-view-mode', viewMode)
}, [viewMode])

// Toggle button UI
<div className="flex items-center gap-2">
  <Button
    variant={viewMode === 'tree' ? 'default' : 'outline'}
    size="icon"
    onClick={() => setViewMode('tree')}
    title="Tree view"
  >
    <FolderTree className="h-4 w-4" />
  </Button>
  <Button
    variant={viewMode === 'table' ? 'default' : 'outline'}
    size="icon"
    onClick={() => setViewMode('table')}
    title="Table view"
  >
    <TableIcon className="h-4 w-4" />
  </Button>
</div>
```

**Step 2: Commit**

```bash
git add frontend/src/pages/Rules.tsx
git commit -m "feat(frontend): add tree/table view toggle with localStorage"
```

---

### Task 15: Rules List - Tree View Component

**Files:**
- Create: `frontend/src/components/RulesTreeView.tsx`

**Step 1: Create tree view component**

```typescript
// frontend/src/components/RulesTreeView.tsx
import { useState } from 'react'
import { ChevronRight, ChevronDown, FileText } from 'lucide-react'
import { Rule, IndexPattern } from '@/lib/api'
import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'

interface RulesTreeViewProps {
  rules: Rule[]
  indexPatterns: IndexPattern[]
  onRuleClick: (rule: Rule) => void
}

export function RulesTreeView({ rules, indexPatterns, onRuleClick }: RulesTreeViewProps) {
  const [expandedPatterns, setExpandedPatterns] = useState<Set<string>>(new Set())

  // Group rules by index pattern
  const rulesByPattern = rules.reduce((acc, rule) => {
    const patternId = rule.index_pattern_id
    if (!acc[patternId]) {
      acc[patternId] = []
    }
    acc[patternId].push(rule)
    return acc
  }, {} as Record<string, Rule[]>)

  const togglePattern = (patternId: string) => {
    setExpandedPatterns(prev => {
      const newSet = new Set(prev)
      if (newSet.has(patternId)) {
        newSet.delete(patternId)
      } else {
        newSet.add(patternId)
      }
      return newSet
    })
  }

  const getPatternName = (patternId: string) => {
    return indexPatterns.find(p => p.id === patternId)?.name || 'Unknown'
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-red-500'
      case 'high': return 'bg-orange-500'
      case 'medium': return 'bg-yellow-500'
      case 'low': return 'bg-blue-500'
      default: return 'bg-gray-500'
    }
  }

  return (
    <div className="space-y-1">
      {Object.entries(rulesByPattern).map(([patternId, patternRules]) => (
        <div key={patternId}>
          <button
            className="flex items-center gap-2 w-full p-2 hover:bg-muted rounded-md text-left"
            onClick={() => togglePattern(patternId)}
          >
            {expandedPatterns.has(patternId) ? (
              <ChevronDown className="h-4 w-4" />
            ) : (
              <ChevronRight className="h-4 w-4" />
            )}
            <span className="font-medium">{getPatternName(patternId)}</span>
            <Badge variant="secondary" className="ml-auto">
              {patternRules.length}
            </Badge>
          </button>

          {expandedPatterns.has(patternId) && (
            <div className="ml-6 space-y-1">
              {patternRules.map(rule => (
                <button
                  key={rule.id}
                  className="flex items-center gap-2 w-full p-2 hover:bg-muted rounded-md text-left"
                  onClick={() => onRuleClick(rule)}
                >
                  <FileText className="h-4 w-4 text-muted-foreground" />
                  <span className={cn(
                    rule.status === 'disabled' && 'text-muted-foreground'
                  )}>
                    {rule.title}
                  </span>
                  <div className={cn('w-2 h-2 rounded-full ml-auto', getSeverityColor(rule.severity))} />
                  {rule.deployed_at && (
                    <Badge variant="outline" className="text-xs">deployed</Badge>
                  )}
                </button>
              ))}
            </div>
          )}
        </div>
      ))}
    </div>
  )
}
```

**Step 2: Commit**

```bash
git add frontend/src/components/RulesTreeView.tsx
git commit -m "feat(frontend): add RulesTreeView component"
```

---

### Task 16: Rules List - Filters

**Files:**
- Modify: `frontend/src/pages/Rules.tsx`

**Step 1: Add filter state and UI**

```typescript
// Filter state
const [filters, setFilters] = useState({
  indexPattern: [] as string[],
  severity: [] as string[],
  status: [] as string[],
  sigmaStatus: [] as string[],
  deployed: 'any' as 'any' | 'yes' | 'no',
  search: '',
})

// Filter the rules
const filteredRules = useMemo(() => {
  return rules.filter(rule => {
    if (filters.indexPattern.length > 0 && !filters.indexPattern.includes(rule.index_pattern_id)) {
      return false
    }
    if (filters.severity.length > 0 && !filters.severity.includes(rule.severity)) {
      return false
    }
    if (filters.status.length > 0 && !filters.status.includes(rule.status)) {
      return false
    }
    if (filters.sigmaStatus.length > 0 && !filters.sigmaStatus.includes(rule.sigma_status || 'stable')) {
      return false
    }
    if (filters.deployed === 'yes' && !rule.deployed_at) {
      return false
    }
    if (filters.deployed === 'no' && rule.deployed_at) {
      return false
    }
    if (filters.search && !rule.title.toLowerCase().includes(filters.search.toLowerCase())) {
      return false
    }
    return true
  })
}, [rules, filters])

// Filter UI
<div className="flex flex-wrap gap-2 mb-4">
  <Input
    placeholder="Search rules..."
    value={filters.search}
    onChange={(e) => setFilters(f => ({ ...f, search: e.target.value }))}
    className="w-64"
  />

  <MultiSelect
    placeholder="Index Pattern"
    options={indexPatterns.map(p => ({ value: p.id, label: p.name }))}
    selected={filters.indexPattern}
    onChange={(selected) => setFilters(f => ({ ...f, indexPattern: selected }))}
  />

  <MultiSelect
    placeholder="Severity"
    options={[
      { value: 'critical', label: 'Critical' },
      { value: 'high', label: 'High' },
      { value: 'medium', label: 'Medium' },
      { value: 'low', label: 'Low' },
      { value: 'informational', label: 'Informational' },
    ]}
    selected={filters.severity}
    onChange={(selected) => setFilters(f => ({ ...f, severity: selected }))}
  />

  <MultiSelect
    placeholder="Status"
    options={[
      { value: 'enabled', label: 'Enabled' },
      { value: 'disabled', label: 'Disabled' },
      { value: 'snoozed', label: 'Snoozed' },
    ]}
    selected={filters.status}
    onChange={(selected) => setFilters(f => ({ ...f, status: selected }))}
  />

  <Select
    value={filters.deployed}
    onValueChange={(value) => setFilters(f => ({ ...f, deployed: value as 'any' | 'yes' | 'no' }))}
  >
    <SelectTrigger className="w-32">
      <SelectValue placeholder="Deployed" />
    </SelectTrigger>
    <SelectContent>
      <SelectItem value="any">Any</SelectItem>
      <SelectItem value="yes">Deployed</SelectItem>
      <SelectItem value="no">Not Deployed</SelectItem>
    </SelectContent>
  </Select>
</div>
```

**Step 2: Commit**

```bash
git add frontend/src/pages/Rules.tsx
git commit -m "feat(frontend): add filters to rules list"
```

---

### Task 17: Rule Comments Model

**Files:**
- Create: `backend/app/models/rule_comment.py`
- Modify: `backend/app/models/__init__.py`

**Step 1: Create rule comment model**

```python
# backend/app/models/rule_comment.py
"""
Rule comments for activity timeline.
"""

import uuid
from datetime import datetime
from sqlalchemy import String, Text, DateTime, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, UUIDMixin, TimestampMixin


class RuleComment(Base, UUIDMixin, TimestampMixin):
    """Comment on a rule, shown in activity timeline."""

    __tablename__ = "rule_comments"

    rule_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("rules.id", ondelete="CASCADE"))
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    content: Mapped[str] = mapped_column(Text)

    # Relationships
    user = relationship("User", lazy="selectin")
```

**Step 2: Update models __init__.py**

```python
from app.models.rule_comment import RuleComment
```

**Step 3: Generate migration**

```bash
docker compose -f docker-compose.dev.yml run --rm backend alembic revision --autogenerate -m "add_rule_comments_table"
docker compose -f docker-compose.dev.yml run --rm backend alembic upgrade head
```

**Step 4: Commit**

```bash
git add backend/app/models/rule_comment.py backend/app/models/__init__.py backend/alembic/versions/
git commit -m "feat(models): add RuleComment model"
```

---

### Task 18: Rule Comments API

**Files:**
- Modify: `backend/app/api/rules.py`

**Step 1: Add comment endpoints**

```python
from app.models.rule_comment import RuleComment

class RuleCommentCreate(BaseModel):
    content: str

class RuleCommentResponse(BaseModel):
    id: str
    rule_id: str
    user_id: str | None
    user_email: str | None
    content: str
    created_at: datetime

@router.get("/{rule_id}/comments", response_model=list[RuleCommentResponse])
async def list_rule_comments(
    rule_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    """List all comments for a rule."""
    result = await db.execute(
        select(RuleComment)
        .where(RuleComment.rule_id == rule_id)
        .order_by(RuleComment.created_at.desc())
    )
    comments = result.scalars().all()
    return [
        RuleCommentResponse(
            id=str(c.id),
            rule_id=str(c.rule_id),
            user_id=str(c.user_id) if c.user_id else None,
            user_email=c.user.email if c.user else None,
            content=c.content,
            created_at=c.created_at,
        )
        for c in comments
    ]

@router.post("/{rule_id}/comments", response_model=RuleCommentResponse)
async def create_rule_comment(
    rule_id: UUID,
    data: RuleCommentCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    """Add a comment to a rule."""
    comment = RuleComment(
        rule_id=rule_id,
        user_id=current_user.id,
        content=data.content,
    )
    db.add(comment)
    await db.commit()
    await db.refresh(comment)

    await audit_log(db, current_user.id, "rule.comment", "rule", str(rule_id),
                    {"comment_id": str(comment.id)})

    return RuleCommentResponse(
        id=str(comment.id),
        rule_id=str(comment.rule_id),
        user_id=str(comment.user_id),
        user_email=current_user.email,
        content=comment.content,
        created_at=comment.created_at,
    )
```

**Step 2: Commit**

```bash
git add backend/app/api/rules.py
git commit -m "feat(api): add rule comments endpoints"
```

---

### Task 19: Activity Panel - Rule Activity API

**Files:**
- Modify: `backend/app/api/rules.py`

**Step 1: Add activity endpoint that combines versions, deploys, comments**

```python
class ActivityItem(BaseModel):
    type: str  # 'version', 'deploy', 'undeploy', 'comment'
    timestamp: datetime
    user_email: str | None
    data: dict

@router.get("/{rule_id}/activity", response_model=list[ActivityItem])
async def get_rule_activity(
    rule_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    """Get unified activity timeline for a rule."""
    activities = []

    # Get versions
    rule = await db.get(Rule, rule_id)
    if rule:
        versions_result = await db.execute(
            select(RuleVersion)
            .where(RuleVersion.rule_id == rule_id)
            .order_by(RuleVersion.version_number.desc())
        )
        for v in versions_result.scalars():
            activities.append(ActivityItem(
                type='version',
                timestamp=v.created_at,
                user_email=None,  # TODO: track who created version
                data={
                    'version_number': v.version_number,
                    'yaml_content': v.yaml_content,
                }
            ))

    # Get comments
    comments_result = await db.execute(
        select(RuleComment)
        .where(RuleComment.rule_id == rule_id)
    )
    for c in comments_result.scalars():
        activities.append(ActivityItem(
            type='comment',
            timestamp=c.created_at,
            user_email=c.user.email if c.user else None,
            data={'content': c.content, 'id': str(c.id)}
        ))

    # Get deploy/undeploy events from audit log
    audit_result = await db.execute(
        select(AuditLog)
        .where(
            AuditLog.resource_id == str(rule_id),
            AuditLog.action.in_(['rule.deploy', 'rule.undeploy'])
        )
    )
    for a in audit_result.scalars():
        activities.append(ActivityItem(
            type='deploy' if a.action == 'rule.deploy' else 'undeploy',
            timestamp=a.created_at,
            user_email=a.user_email,
            data=a.details or {}
        ))

    # Sort by timestamp descending
    activities.sort(key=lambda x: x.timestamp, reverse=True)

    return activities
```

**Step 2: Commit**

```bash
git add backend/app/api/rules.py
git commit -m "feat(api): add rule activity timeline endpoint"
```

---

### Task 20: Activity Panel Frontend

**Files:**
- Create: `frontend/src/components/ActivityPanel.tsx`
- Modify: `frontend/src/pages/RuleEditor.tsx`

**Step 1: Create ActivityPanel component**

```typescript
// frontend/src/components/ActivityPanel.tsx
import { useState, useEffect } from 'react'
import { X, GitCommit, Rocket, MessageSquare, RotateCcw } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Textarea } from '@/components/ui/textarea'
import { rulesApi, ActivityItem } from '@/lib/api'
import { formatDistanceToNow } from 'date-fns'

interface ActivityPanelProps {
  ruleId: string
  isOpen: boolean
  onClose: () => void
  onRestore: (versionNumber: number) => void
}

export function ActivityPanel({ ruleId, isOpen, onClose, onRestore }: ActivityPanelProps) {
  const [activities, setActivities] = useState<ActivityItem[]>([])
  const [isLoading, setIsLoading] = useState(false)
  const [newComment, setNewComment] = useState('')
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [expandedVersion, setExpandedVersion] = useState<number | null>(null)

  useEffect(() => {
    if (isOpen && ruleId) {
      loadActivity()
    }
  }, [isOpen, ruleId])

  const loadActivity = async () => {
    setIsLoading(true)
    try {
      const data = await rulesApi.getActivity(ruleId)
      setActivities(data)
    } catch (err) {
      console.error('Failed to load activity:', err)
    } finally {
      setIsLoading(false)
    }
  }

  const handleAddComment = async () => {
    if (!newComment.trim()) return
    setIsSubmitting(true)
    try {
      await rulesApi.addComment(ruleId, newComment)
      setNewComment('')
      loadActivity()
    } catch (err) {
      console.error('Failed to add comment:', err)
    } finally {
      setIsSubmitting(false)
    }
  }

  if (!isOpen) return null

  return (
    <div className="fixed right-0 top-0 h-full w-96 bg-background border-l shadow-lg z-50 flex flex-col">
      <div className="flex items-center justify-between p-4 border-b">
        <h2 className="font-semibold">Activity</h2>
        <Button variant="ghost" size="icon" onClick={onClose}>
          <X className="h-4 w-4" />
        </Button>
      </div>

      <div className="flex-1 overflow-auto p-4 space-y-4">
        {isLoading ? (
          <div className="text-center text-muted-foreground">Loading...</div>
        ) : (
          activities.map((activity, idx) => (
            <div key={idx} className="flex gap-3">
              <div className="flex-shrink-0 mt-1">
                {activity.type === 'version' && <GitCommit className="h-4 w-4 text-blue-500" />}
                {activity.type === 'deploy' && <Rocket className="h-4 w-4 text-green-500" />}
                {activity.type === 'undeploy' && <Rocket className="h-4 w-4 text-orange-500" />}
                {activity.type === 'comment' && <MessageSquare className="h-4 w-4 text-purple-500" />}
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 text-sm">
                  {activity.type === 'version' && (
                    <>
                      <span className="font-medium">v{activity.data.version_number}</span>
                      <span className="text-muted-foreground">created</span>
                    </>
                  )}
                  {activity.type === 'deploy' && (
                    <span className="text-green-600">Deployed</span>
                  )}
                  {activity.type === 'undeploy' && (
                    <span className="text-orange-600">Undeployed</span>
                  )}
                  {activity.type === 'comment' && (
                    <span className="font-medium">{activity.user_email}</span>
                  )}
                </div>

                {activity.type === 'comment' && (
                  <p className="text-sm mt-1">{activity.data.content}</p>
                )}

                {activity.type === 'version' && (
                  <div className="mt-1">
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-6 text-xs"
                      onClick={() => onRestore(activity.data.version_number)}
                    >
                      <RotateCcw className="h-3 w-3 mr-1" />
                      Restore
                    </Button>
                  </div>
                )}

                <div className="text-xs text-muted-foreground mt-1">
                  {formatDistanceToNow(new Date(activity.timestamp), { addSuffix: true })}
                </div>
              </div>
            </div>
          ))
        )}
      </div>

      <div className="p-4 border-t">
        <Textarea
          placeholder="Add a comment..."
          value={newComment}
          onChange={(e) => setNewComment(e.target.value)}
          className="mb-2"
          rows={2}
        />
        <Button
          onClick={handleAddComment}
          disabled={isSubmitting || !newComment.trim()}
          className="w-full"
        >
          {isSubmitting ? 'Adding...' : 'Add Comment'}
        </Button>
      </div>
    </div>
  )
}
```

**Step 2: Integrate into RuleEditor**

Add to `frontend/src/pages/RuleEditor.tsx`:

```typescript
import { ActivityPanel } from '@/components/ActivityPanel'

// State
const [isActivityOpen, setIsActivityOpen] = useState(false)

// Button in header
<Button variant="outline" onClick={() => setIsActivityOpen(true)}>
  Activity
</Button>

// Panel at end of component
<ActivityPanel
  ruleId={id!}
  isOpen={isActivityOpen}
  onClose={() => setIsActivityOpen(false)}
  onRestore={handleRestoreVersion}
/>
```

**Step 3: Commit**

```bash
git add frontend/src/components/ActivityPanel.tsx frontend/src/pages/RuleEditor.tsx
git commit -m "feat(frontend): add Activity panel with comments and version history"
```

---

## Group C: Data Export & Audit

### Task 21: Export API - Single Rule

**Files:**
- Create: `backend/app/api/export.py`
- Modify: `backend/app/main.py`

**Step 1: Create export API**

```python
# backend/app/api/export.py
"""
Export API for rules and configuration backup.
"""

import io
import zipfile
import json
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Response
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_admin
from app.db.session import get_db
from app.models.user import User
from app.models.rule import Rule
from app.models.index_pattern import IndexPattern
from app.models.setting import Setting

router = APIRouter(prefix="/export", tags=["export"])


@router.get("/rules/{rule_id}")
async def export_single_rule(
    rule_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    """Export a single rule as YAML file."""
    rule = await db.get(Rule, rule_id)
    if not rule:
        raise HTTPException(404, "Rule not found")

    # Sanitize title for filename
    safe_title = "".join(c if c.isalnum() or c in '-_' else '_' for c in rule.title)
    filename = f"{safe_title}.yml"

    return Response(
        content=rule.yaml_content,
        media_type="application/x-yaml",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )


@router.post("/rules/bulk")
async def export_bulk_rules(
    rule_ids: list[str],
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    """Export multiple rules as ZIP file."""
    result = await db.execute(
        select(Rule).where(Rule.id.in_(rule_ids))
    )
    rules = result.scalars().all()

    # Create ZIP in memory
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
        for rule in rules:
            safe_title = "".join(c if c.isalnum() or c in '-_' else '_' for c in rule.title)
            zf.writestr(f"{safe_title}.yml", rule.yaml_content)

    zip_buffer.seek(0)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")

    return StreamingResponse(
        zip_buffer,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="chad-rules-{timestamp}.zip"'}
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
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
        for rule in rules:
            safe_title = "".join(c if c.isalnum() or c in '-_' else '_' for c in rule.title)
            zf.writestr(f"{safe_title}.yml", rule.yaml_content)

    zip_buffer.seek(0)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")

    return StreamingResponse(
        zip_buffer,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="chad-rules-all-{timestamp}.zip"'}
    )


@router.get("/config")
async def export_config(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_admin)],
):
    """Export configuration backup as JSON (no secrets)."""
    # Get index patterns (without tokens)
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
        if not s.key.startswith('secret_') and not s.key.endswith('_token')
    }

    # Get role permissions
    # ... (include if implemented)

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
        headers={"Content-Disposition": f'attachment; filename="chad-config-{timestamp}.json"'}
    )
```

**Step 2: Register router**

Add to `backend/app/main.py`:
```python
from app.api.export import router as export_router
app.include_router(export_router, prefix="/api")
```

**Step 3: Commit**

```bash
git add backend/app/api/export.py backend/app/main.py
git commit -m "feat(api): add export endpoints for rules and config"
```

---

### Task 22: Export UI

**Files:**
- Modify: `frontend/src/pages/Settings.tsx`
- Modify: `frontend/src/pages/RuleEditor.tsx`
- Modify: `frontend/src/pages/Rules.tsx`

**Step 1: Add export section to Settings**

```typescript
// In Settings.tsx, add Export tab content
<TabsContent value="export" className="space-y-6">
  <Card>
    <CardHeader>
      <CardTitle>Export Rules</CardTitle>
      <CardDescription>Download rules as Sigma YAML files</CardDescription>
    </CardHeader>
    <CardContent className="space-y-4">
      <Button onClick={() => window.location.href = '/api/export/rules'}>
        Export All Rules (ZIP)
      </Button>
    </CardContent>
  </Card>

  <Card>
    <CardHeader>
      <CardTitle>Configuration Backup</CardTitle>
      <CardDescription>Download system configuration (no secrets)</CardDescription>
    </CardHeader>
    <CardContent>
      <Button onClick={() => window.location.href = '/api/export/config'}>
        Export Configuration (JSON)
      </Button>
      <p className="text-sm text-muted-foreground mt-2">
        Includes: index patterns, settings, webhooks, role permissions
      </p>
    </CardContent>
  </Card>
</TabsContent>
```

**Step 2: Add export to RuleEditor dropdown**

```typescript
// In RuleEditor.tsx header dropdown
<DropdownMenuItem onClick={() => window.location.href = `/api/export/rules/${id}`}>
  Export Rule
</DropdownMenuItem>
```

**Step 3: Add bulk export to Rules page action bar**

```typescript
// In bulk action bar
<Button
  size="sm"
  variant="outline"
  onClick={() => {
    // POST to bulk export endpoint
    const form = document.createElement('form')
    form.method = 'POST'
    form.action = '/api/export/rules/bulk'
    // ... submit with rule_ids
  }}
>
  Export
</Button>
```

**Step 4: Commit**

```bash
git add frontend/src/pages/Settings.tsx frontend/src/pages/RuleEditor.tsx frontend/src/pages/Rules.tsx
git commit -m "feat(frontend): add export UI to Settings and Rules pages"
```

---

### Task 23: Audit to OpenSearch Setting

**Files:**
- Modify: `backend/app/services/audit.py`

**Step 1: Add OpenSearch dual-write option**

```python
# Modify audit_log function in backend/app/services/audit.py

from app.services.settings import get_setting
from app.api.deps import get_opensearch_client_optional

async def audit_log(
    db: AsyncSession,
    user_id: uuid.UUID | None,
    action: str,
    resource_type: str,
    resource_id: str | None,
    details: dict | None = None,
    ip_address: str | None = None,
):
    """Log an audit event to PostgreSQL and optionally OpenSearch."""

    # Get user email for denormalization
    user_email = None
    if user_id:
        user = await db.get(User, user_id)
        if user:
            user_email = user.email

    # Create PostgreSQL record
    log_entry = AuditLog(
        user_id=user_id,
        user_email=user_email,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details,
        ip_address=ip_address,
    )
    db.add(log_entry)
    await db.commit()

    # Check if OpenSearch dual-write is enabled
    opensearch_enabled = await get_setting(db, "audit_opensearch_enabled", False)
    if opensearch_enabled:
        try:
            os_client = get_opensearch_client_optional()
            if os_client:
                os_client.index(
                    index="chad-audit-logs",
                    body={
                        "timestamp": log_entry.created_at.isoformat(),
                        "user_id": str(user_id) if user_id else None,
                        "user_email": user_email,
                        "action": action,
                        "resource_type": resource_type,
                        "resource_id": resource_id,
                        "details": details,
                        "ip_address": ip_address,
                    }
                )
        except Exception as e:
            # Log warning but don't fail the operation
            print(f"Failed to write audit to OpenSearch: {e}")
```

**Step 2: Commit**

```bash
git add backend/app/services/audit.py
git commit -m "feat(audit): add optional OpenSearch dual-write"
```

---

### Task 24: Audit OpenSearch Setting UI

**Files:**
- Modify: `frontend/src/pages/Settings.tsx`

**Step 1: Add audit OpenSearch toggle**

```typescript
// Add state
const [auditOpenSearchEnabled, setAuditOpenSearchEnabled] = useState(false)

// Add to Audit tab
<Card>
  <CardHeader>
    <CardTitle>Audit Log Storage</CardTitle>
    <CardDescription>
      Configure where audit logs are stored
    </CardDescription>
  </CardHeader>
  <CardContent className="space-y-4">
    <div className="flex items-center justify-between">
      <div>
        <Label>Send to OpenSearch</Label>
        <p className="text-sm text-muted-foreground">
          Also write audit logs to chad-audit-logs index for SIEM integration
        </p>
      </div>
      <Switch
        checked={auditOpenSearchEnabled}
        onCheckedChange={setAuditOpenSearchEnabled}
      />
    </div>
  </CardContent>
</Card>
```

**Step 2: Commit**

```bash
git add frontend/src/pages/Settings.tsx
git commit -m "feat(frontend): add audit OpenSearch toggle in Settings"
```

---

## Group D: Quality of Life

### Task 25: OIDC Role Management

**Files:**
- Modify: `frontend/src/pages/Users.tsx`
- Modify: `backend/app/api/users.py`

**Step 1: Update Users page to allow role change when OIDC mapping disabled**

```typescript
// In Users.tsx, modify the role select to be conditional
const canEditRole = (user: User) => {
  // Can always edit local users
  if (user.auth_method === 'local') return true
  // Can edit OIDC users only if role mapping is disabled
  return !oidcRoleMappingEnabled
}

// In the role select
<Select
  value={user.role}
  onValueChange={(value) => handleRoleChange(user.id, value)}
  disabled={!canEditRole(user)}
>
  {/* options */}
</Select>

{!canEditRole(user) && (
  <p className="text-xs text-muted-foreground">
    Role managed by SSO
  </p>
)}
```

**Step 2: Update backend to allow role change for OIDC users when mapping disabled**

```python
# In backend/app/api/users.py update_user endpoint
# Check if OIDC role mapping is enabled before allowing role change
oidc_role_mapping = await get_setting(db, "oidc_role_mapping_enabled", False)

if user.auth_method == "sso" and oidc_role_mapping and data.role is not None:
    raise HTTPException(400, "Cannot change role for SSO users when role mapping is enabled")
```

**Step 3: Commit**

```bash
git add frontend/src/pages/Users.tsx backend/app/api/users.py
git commit -m "feat: allow OIDC user role changes when role mapping disabled"
```

---

### Task 26: YAML Auto-formatting

**Files:**
- Modify: `backend/requirements.txt`
- Modify: `backend/app/api/rules.py`
- Modify: `frontend/src/pages/RuleEditor.tsx`

**Step 1: Add ruamel.yaml to requirements**

```
ruamel.yaml>=0.18.0
```

**Step 2: Add format endpoint**

```python
# In backend/app/api/rules.py
from ruamel.yaml import YAML
import io

class FormatRequest(BaseModel):
    yaml_content: str

class FormatResponse(BaseModel):
    formatted: str

@router.post("/format", response_model=FormatResponse)
async def format_yaml(
    data: FormatRequest,
    _: Annotated[User, Depends(get_current_user)],
):
    """Format YAML content, preserving comments."""
    yaml = YAML()
    yaml.preserve_quotes = True
    yaml.indent(mapping=2, sequence=4, offset=2)

    try:
        # Parse
        parsed = yaml.load(io.StringIO(data.yaml_content))

        # Dump to string
        output = io.StringIO()
        yaml.dump(parsed, output)
        formatted = output.getvalue()

        return FormatResponse(formatted=formatted)
    except Exception as e:
        raise HTTPException(400, f"Invalid YAML: {str(e)}")
```

**Step 3: Add format button to RuleEditor**

```typescript
// In RuleEditor.tsx
const handleFormat = async () => {
  try {
    const result = await rulesApi.format(yamlContent)
    setYamlContent(result.formatted)
  } catch (err) {
    setError(err instanceof Error ? err.message : 'Format failed')
  }
}

// Button in toolbar
<Button variant="outline" size="sm" onClick={handleFormat}>
  Format
</Button>
```

**Step 4: Commit**

```bash
git add backend/requirements.txt backend/app/api/rules.py frontend/src/pages/RuleEditor.tsx
git commit -m "feat: add YAML auto-formatting with ruamel.yaml"
```

---

### Task 27-30: Dialog Standards Audit

**Files to audit and fix:**
- `frontend/src/pages/*.tsx` - Check for confirm(), alert(), prompt()

**Step 1: Search for browser dialogs**

```bash
grep -r "confirm\|alert\|prompt" frontend/src/pages/ --include="*.tsx"
```

**Step 2: Replace each with DeleteConfirmModal or custom Dialog**

For each occurrence found:
1. Add local state for dialog open/close
2. Replace confirm() with Dialog component
3. Add error state within dialog if applicable

**Step 3: Commit after each file fixed**

---

### Task 31-32: Audit Logging Gaps

**Files:**
- Review all API endpoints in `backend/app/api/`

**Step 1: Identify missing audit calls**

Check these endpoints have audit logging:
- Settings changes (all of them)
- SigmaHQ sync enable/disable
- Webhook create/update/delete
- Index pattern changes
- User changes
- Permission changes

**Step 2: Add missing audit_log calls**

For each missing audit event, add:
```python
await audit_log(db, current_user.id, "resource.action", "resource_type", resource_id, {"details": "here"})
```

**Step 3: Commit**

```bash
git add backend/app/api/
git commit -m "fix(audit): add missing audit events for settings and webhooks"
```

---

## Final Verification

After all tasks complete:

1. Run all tests:
```bash
docker compose -f docker-compose.dev.yml run --rm backend pytest
docker compose -f docker-compose.dev.yml run --rm frontend npm test
```

2. Manual testing checklist:
- [ ] Rate limiting: Lock account after 5 failed logins
- [ ] Bulk operations: Select multiple rules, enable/disable/delete
- [ ] Tree view: Rules grouped by index pattern
- [ ] Activity panel: Shows versions, deploys, comments
- [ ] Export: Single rule YAML, bulk ZIP, config JSON
- [ ] Audit to OpenSearch: Toggle enabled, check index created
- [ ] Role permissions: Customize analyst/viewer permissions
- [ ] OIDC roles: Can edit when mapping disabled
- [ ] YAML format: Button works, preserves structure
- [ ] Dialogs: No browser confirm() anywhere

3. Final commit:
```bash
git add .
git commit -m "feat: complete Phase 7 implementation"
```
