# Integration Tests

This directory contains integration tests that test the interaction between multiple components, external services, and end-to-end flows.

## Running Integration Tests

### Run all integration tests:
```bash
cd backend
pytest tests/integration/ -v
```

### Run specific integration test file:
```bash
pytest tests/integration/test_auth_integration.py -v
```

### Run with coverage:
```bash
pytest tests/integration/ --cov=app --cov-report=html
```

### Skip integration tests (fast feedback during development):
```bash
pytest tests/ -m "not integration"
```

## Test Dependencies

Integration tests require additional dependencies:

```bash
pip install testcontainers[postgresql] httpx
```

## Test Categories

### 1. Authentication Flow (`test_auth_integration.py`)
- Initial setup flow
- Local authentication login
- Token validation
- Protected route access

### 2. OpenSearch Integration (`test_opensearch_integration.py`)
- Connection validation
- Percolator query functionality
- Index and query operations

### 3. Scheduler Integration (`test_scheduler_integration.py`)
- Service lifecycle (start/stop)
- Job registration and execution
- Job persistence to database
- Error handling

## Requirements

Integration tests marked with `@pytest.mark.integration` require:
- Running PostgreSQL (or testcontainers will spin one up)
- OpenSearch instance (for OpenSearch-specific tests)

## CI/CD Integration

To add integration tests to your CI pipeline:

```yaml
test-integration:
  stage: test
  services:
    - postgres:16-alpine
    - opensearch:latest
  script:
    - cd backend
    - pip install testcontainers[postgresql]
    - pytest tests/integration/ -v
  only:
    - main
    - merge_requests
```

## Writing New Integration Tests

When adding new integration tests:

1. Import necessary modules and fixtures
2. Use `@pytest.mark.asyncio` for async tests
3. Use `@pytest.mark.integration` for tests requiring external services
4. Use descriptive test names that explain what's being tested
5. Clean up resources in `finally` blocks
6. Make tests independent and idempotent

Example:
```python
@pytest.mark.integration
@pytest.mark.asyncio
async def test_service_interaction(db_session: AsyncSession):
    """Test that service A correctly calls service B."""
    # Setup
    service_a = ServiceA(db_session)

    # Execute
    result = await service_a.perform_action()

    # Verify
    assert result.success is True

    # Cleanup
    await service_a.cleanup()
```
