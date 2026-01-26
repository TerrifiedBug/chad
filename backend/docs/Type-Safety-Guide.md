# Type Safety Improvement Guide

## Overview

CHAD uses `mypy` for static type checking to catch bugs at compile time.

## Running Type Checks

### Check all code
```bash
# In Docker
docker compose -f docker-compose.dev.yml run --rm backend mypy app

# Or with ruff (faster, includes type checking)
docker compose -f docker-compose.dev.yml run --rm backend ruff check
```

### Check specific file
```bash
docker compose -f docker-compose.dev.yml run --rm backend mypy app/api/rules.py
```

### Watch mode (during development)
```bash
docker compose -f docker-compose.dev.yml run --rm backend mypy --watch app
```

## Common Type Errors and Fixes

### Error: "has no attribute"

**Problem:**
```python
# mypy error: Item "None" of "Optional[str]" has no attribute "upper"
def process(text: str | None) -> str:
    return text.upper()  # Error!
```

**Fix:**
```python
def process(text: str | None) -> str:
    if text is None:
        return ""
    return text.upper()

# Or use assertion
def process(text: str | None) -> str:
    assert text is not None
    return text.upper()
```

### Error: "incompatible return value type"

**Problem:**
```python
def get_user() -> User:
    user = db.query(User).first()
    return user  # Error: might be None
```

**Fix:**
```python
from app.core.errors import not_found

def get_user() -> User:
    user = db.query(User).first()
    if user is None:
        raise not_found("User")
    return user
```

### Error: "missing type annotation"

**Problem:**
```python
def calculate(x, y):  # Error: function lacks type annotations
    return x + y
```

**Fix:**
```python
def calculate(x: int, y: int) -> int:
    return x + y
```

### Error: "incompatible item type"

**Problem:**
```python
names: list[str] = ["alice", "bob", 123]  # Error: int incompatible with str
```

**Fix:**
```python
names: list[str] = ["alice", "bob", "123"]  # Convert int to str
```

## Type Annotations Best Practices

### Use `|` for unions (Python 3.10+)
```python
# Good
def process(value: str | int | None) -> str:

# Avoid (older style)
from typing import Union
def process(value: Union[str, int, None]) -> str:
```

### Use `list` and `dict` instead of `List` and `Dict`
```python
# Good (Python 3.9+)
def get_items() -> list[str]:
    return ["a", "b"]

# Avoid (older style)
from typing import List
def get_items() -> List[str]:
    return ["a", "b"]
```

### Use `typing.Annotated` for additional constraints
```python
from typing import Annotated
from pydantic import BaseModel

UserId = Annotated[int, "User ID from database"]

def get_user(user_id: UserId) -> User | None:
    ...
```

## Gradual Type Safety Adoption

### Phase 1: Fix Critical Errors (Week 1)
- Fix all errors in core files (`app/core/`, `app/api/deps.py`)
- Fix errors in frequently used modules (`app/api/auth.py`, `app/api/rules.py`)

### Phase 2: Add Type Hints (Week 2-3)
- Add return types to all functions
- Add parameter types to all functions
- Add type hints to class attributes

### Phase 3: Enable Strict Mode (Month 2)
- Enable `disallow_untyped_defs = true`
- Fix remaining errors
- Add type stubs for third-party libraries if needed

## Type Annotation Examples

### API Endpoints
```python
from fastapi import APIRouter
from sqlalchemy.ext.asyncio import AsyncSession

router = APIRouter()

@router.get("/users/{user_id}")
async def get_user(
    user_id: str,
    db: AsyncSession,  # Use AsyncSession, not Session
) -> UserResponse:  # Always specify return type
    """Get user by ID."""
    ...
```

### Database Models
```python
from sqlalchemy.orm import Mapped, mapped_column

class User(Base):
    """User model."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
```

### Pydantic Models
```python
from pydantic import BaseModel, Field

class RuleCreate(BaseModel):
    """Schema for creating a rule."""

    title: str = Field(..., min_length=1, max_length=255)
    description: str | None = None
    severity: str = Field(default="medium", pattern="^(low|medium|high|critical)$")
```

## Type Checking in CI

Add to `.github/workflows/test.yml`:

```yaml
- name: Type check with mypy
  run: |
    docker compose -f docker-compose.dev.yml run --rm backend mypy app
```

## IDE Integration

### VSCode
Install extensions:
- `ms-python.vscode-pylance` (built-in to Python extension)
- Add to `.vscode/settings.json`:
  ```json
  {
    "python.analysis.typeCheckingMode": "strict",
    "python.linting.mypyEnabled": true
  }
  ```

### PyCharm
- Settings → Python → Type Checking → Check type hints
- Settings → Editor → Inspections → Python → Type hints

## Benefits

1. **Catch Bugs Early**: Find errors before runtime
2. **Better IDE Support**: Autocomplete and inline errors
3. **Self-Documenting**: Types serve as documentation
4. **Refactoring Safety**: Catch breaking changes immediately
5. **Code Quality**: Encourages better code structure

## Resources

- [mypy documentation](https://mypy.readthedocs.io/)
- [Python typing documentation](https://docs.python.org/3/library/typing.html)
- [FastAPI types](https://fastapi.tiangolo.com/python-types/)
