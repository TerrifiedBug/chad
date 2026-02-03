"""Circuit breaker status and management endpoints."""

from typing import Annotated

from fastapi import APIRouter, Depends

from app.api.deps import get_current_user, require_admin
from app.core.circuit_breaker import _circuit_breakers, get_circuit_breaker
from app.models.user import User

router = APIRouter(prefix="/circuit-breakers", tags=["circuit-breakers"])


@router.get("")
async def list_circuit_breakers(
    current_user: Annotated[User, Depends(get_current_user)],
):
    """List all circuit breakers and their current states."""
    return [
        {
            "service_name": name,
            "state": cb.get_state().value,
            "failure_count": cb.get_failure_count(),
        }
        for name, cb in _circuit_breakers.items()
    ]


@router.post("/{service_name}/reset")
async def reset_circuit_breaker(
    service_name: str,
    current_user: Annotated[User, Depends(require_admin)],
):
    """Manually reset a circuit breaker to CLOSED state.

    This can be useful after fixing an external service issue.
    """
    cb = get_circuit_breaker(service_name)
    cb.reset()

    return {
        "message": f"Circuit breaker for '{service_name}' has been reset",
        "service_name": service_name,
        "new_state": "closed",
    }
