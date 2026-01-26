# Code Deduplication Guide

## Overview

This guide shows how to use utility functions and decorators to reduce code duplication.

## Permission Checking

### Before (Duplicated)
```python
from app.api.deps import require_permission_dep

@router.get("/rules")
async def list_rules(
    current_user: Annotated[User, Depends(require_permission_dep("view_rules"))],
):
    ...

@router.get("/alerts")
async def list_alerts(
    current_user: Annotated[User, Depends(require_permission_dep("view_alerts"))],
):
    ...
```

### After (Simplified)
```python
from app.utils.decorators import Permissions

@router.get("/rules")
async def list_rules(
    _: Annotated[User, Depends(Permissions.VIEW_RULES)],
):
    ...

@router.get("/alerts")
async def list_alerts(
    _: Annotated[User, Depends(Permissions.VIEW_ALERTS)],
):
    ...
```

## Generic CRUD Operations

### Before (Repeated CRUD logic)
```python
@router.post("/rules")
async def create_rule(
    rule_data: RuleCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    rule = Rule(**rule_data.model_dump())
    db.add(rule)
    await db.commit()
    await db.refresh(rule)
    return rule

@router.post("/alerts")
async def create_alert(
    alert_data: AlertCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    alert = Alert(**alert_data.model_dump())
    db.add(alert)
    await db.commit()
    await db.refresh(alert)
    return alert
```

### After (Generic CRUD)
```python
from app.utils.crud import CRUDOperations

# Define CRUD operations for each model
rule_crud = CRUDOperations[Rule, RuleCreate, RuleUpdate](Rule)
alert_crud = CRUDOperations[Alert, AlertCreate, AlertUpdate](Alert)

# Use in endpoints
@router.post("/rules")
async def create_rule(
    rule_data: RuleCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    return await rule_crud.create(db, rule_data)

@router.post("/alerts")
async def create_alert(
    alert_data: AlertCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    return await alert_crud.create(db, alert_data)
```

## Error Handling

### Before (Repeated error checks)
```python
@router.get("/rules/{rule_id}")
async def get_rule(rule_id: str, db: AsyncSession):
    rule = await db.get(Rule, rule_id)
    if rule is None:
        raise HTTPException(404, "Rule not found")
    return rule

@router.get("/alerts/{alert_id}")
async def get_alert(alert_id: str, db: AsyncSession):
    alert = await db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(404, "Alert not found")
    return alert
```

### After (Generic error handling)
```python
from app.utils.crud import get_by_id_or_404
from app.core.errors import not_found

@router.get("/rules/{rule_id}")
async def get_rule(rule_id: str, db: AsyncSession):
    return get_by_id_or_404(db, Rule, rule_id, "Rule")

# Or with CRUD class
@router.get("/rules/{rule_id}")
async def get_rule(rule_id: str, db: AsyncSession):
    return await rule_crud.get_or_404(db, rule_id, "Rule")
```

## Audit Logging

### Before (Repeated audit calls)
```python
@router.post("/rules")
async def create_rule(
    rule_data: RuleCreate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    rule = Rule(**rule_data.model_dump())
    db.add(rule)
    await db.commit()
    await db.refresh(rule)

    # Manual audit logging
    await audit_log(
        db,
        current_user.id,
        "rule.create",
        "rule",
        str(rule.id),
        {"title": rule.title},
        get_client_ip(request),
    )

    return rule
```

### After (Decorator-based)
```python
from app.utils.decorators import with_audit_log

@with_audit_log("create", "rule", lambda kwargs: kwargs["rule_data"].title)
@router.post("/rules")
async def create_rule(
    rule_data: RuleCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    rule = Rule(**rule_data.model_dump())
    db.add(rule)
    await db.commit()
    await db.refresh(rule)
    return rule
```

## Common Patterns

### Get or 404 Pattern
```python
# Before
rule = await db.get(Rule, rule_id)
if rule is None:
    raise HTTPException(404, "Rule not found")

# After
from app.utils.crud import get_by_id_or_404
rule = get_by_id_or_404(db, Rule, rule_id, "Rule")
```

### Pagination Pattern
```python
# Before
result = await db.execute(select(Rule).offset(skip).limit(limit))
rules = result.scalars().all()
return rules

# After
from app.utils.crud import CRUDOperations
rule_crud = CRUDOperations(Rule)
rules = await rule_crud.get_multi(db, skip=skip, limit=limit)
```

### Update Pattern
```python
# Before
update_data = rule_update.model_dump(exclude_unset=True)
for field, value in update_data.items():
    setattr(rule, field, value)
db.add(rule)
await db.commit()
await db.refresh(rule)

# After
from app.utils.crud import CRUDOperations
rule_crud = CRUDOperations(Rule)
rule = await rule_crud.update(db, rule, rule_update)
```

## Creating Custom Utilities

### Example: Timestamp tracking
```python
from app.utils.crud import CRUDOperations

class TimestampedCRUD(CRUDOperations[ModelType, CreateSchemaType, UpdateSchemaType]):
    """CRUD operations with automatic timestamp tracking."""

    async def create(self, db: AsyncSession, obj_in: CreateSchemaType, user_id: str) -> ModelType:
        """Create with timestamps."""
        obj_in_data = obj_in.model_dump()
        obj_in_data["created_at"] = datetime.now(timezone.utc)
        obj_in_data["created_by"] = user_id
        return await super().create(db, obj_in)

    async def update(self, db: AsyncSession, db_obj: ModelType, obj_in: UpdateSchemaType, user_id: str) -> ModelType:
        """Update with timestamps."""
        db_obj.updated_at = datetime.now(timezone.utc)
        db_obj.updated_by = user_id
        return await super().update(db, db_obj, obj_in)
```

## Refactoring Checklist

When refactoring duplicated code:

1. **Identify the pattern**: What's repeated?
2. **Create utility function**: Extract to shared module
3. **Add tests**: Test the utility function
4. **Refactor callers**: Update code to use utility
5. **Remove old code**: Delete duplicated implementations
6. **Verify behavior**: Ensure refactored code works identically

## Benefits

1. **Less code**: Write less, do more
2. **Consistency**: Same behavior everywhere
3. **Easier testing**: Test utilities once
4. **Faster development**: Reuse proven patterns
5. **Easier maintenance**: Fix bugs in one place

## Anti-Patterns to Avoid

### Don't over-abstract
```python
# Bad: Too generic, hard to understand
async def do_crud(model, data, operation):
    ...

# Good: Explicit and type-safe
async def create_rule(data: RuleCreate) -> Rule:
    ...
```

### Don't create utilities for one-off code
```python
# Bad: Only used once
def get_rule_by_id_with_exact_name_and_status():
    ...

# Good: Just write it inline
rule = await db.get(Rule, rule_id)
```

### Don't mix concerns
```python
# Bad: Utility does too many things
def create_rule_and_send_notification_and_log_audit():
    ...

# Good: Separate concerns
rule_crud.create(db, rule_data)
notification_service.send(...)
audit_log(...)
```
