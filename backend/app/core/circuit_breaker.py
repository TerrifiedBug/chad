"""Circuit breaker implementation for external service resilience.

Prevents cascading failures by temporarily disabling calls to failing services.
"""

import asyncio
import logging
import time
from collections.abc import Callable
from enum import Enum
from functools import wraps
from typing import ParamSpec, TypeVar

logger = logging.getLogger(__name__)

P = ParamSpec("P")
T = TypeVar("T")


class CircuitState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"  # Normal operation, requests pass through
    OPEN = "open"  # Circuit is tripped, requests fail fast
    HALF_OPEN = "half_open"  # Testing if service has recovered


class CircuitBreakerError(Exception):
    """Raised when circuit breaker is open."""

    def __init__(self, service_name: str, remaining_time: float | None = None):
        self.service_name = service_name
        self.remaining_time = remaining_time
        message = f"Circuit breaker is OPEN for service '{service_name}'"
        if remaining_time is not None:
            message += f". Retry in {remaining_time:.1f} seconds"
        super().__init__(message)


class CircuitBreaker:
    """Circuit breaker for protecting external service calls.

    Tracks failures and opens the circuit when too many failures occur.
    Automatically closes again after a timeout period.
    """

    def __init__(
        self,
        service_name: str,
        failure_threshold: int = 5,  # Number of failures before opening
        recovery_timeout: float = 60.0,  # Seconds to wait before trying again
        expected_exception: type[Exception] | tuple[type[Exception], ...] = Exception,
    ):
        """Initialize circuit breaker.

        Args:
            service_name: Name of the service being protected (for logging)
            failure_threshold: Number of consecutive failures before opening circuit
            recovery_timeout: Seconds to wait before transitioning from OPEN to HALF_OPEN
            expected_exception: Exception type(s) that count as failures
        """
        self.service_name = service_name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.expected_exception = expected_exception

        self._failure_count = 0
        self._last_failure_time = 0.0
        self._state = CircuitState.CLOSED
        self._lock = asyncio.Lock()

    async def call(self, func: Callable[P, T], *args: P.args, **kwargs: P.kwargs) -> T:
        """Execute a function through the circuit breaker.

        Args:
            func: Function to execute
            *args: Positional arguments for func
            **kwargs: Keyword arguments for func

        Returns:
            Result from func

        Raises:
            CircuitBreakerError: If circuit is OPEN
            Exception: If func raises an exception (counts as failure)
        """
        async with self._lock:
            # Check if we should attempt recovery
            if self._state == CircuitState.OPEN:
                if time.time() - self._last_failure_time >= self.recovery_timeout:
                    logger.info(
                        "Circuit breaker for '%s' transitioning from OPEN to HALF_OPEN",
                        self.service_name,
                    )
                    self._state = CircuitState.HALF_OPEN
                else:
                    # Circuit is still open, fail fast
                    remaining = self.recovery_timeout - (time.time() - self._last_failure_time)
                    raise CircuitBreakerError(self.service_name, remaining)

        try:
            # Execute the function
            if asyncio.iscoroutinefunction(func):
                result = await func(*args, **kwargs)
            else:
                result = func(*args, **kwargs)

            # Success - reset failure count and close circuit
            async with self._lock:
                if self._state == CircuitState.HALF_OPEN:
                    logger.info(
                        "Circuit breaker for '%s' transitioning from HALF_OPEN to CLOSED",
                        self.service_name,
                    )
                self._state = CircuitState.CLOSED
                self._failure_count = 0

            return result

        except self.expected_exception as e:
            # Failure - increment counter and potentially open circuit
            async with self._lock:
                self._failure_count += 1
                self._last_failure_time = time.time()

                if self._failure_count >= self.failure_threshold:
                    if self._state != CircuitState.OPEN:
                        logger.warning(
                            "Circuit breaker for '%s' transitioning from %s to OPEN after %d failures",
                            self.service_name,
                            self._state.value.upper(),
                            self._failure_count,
                        )
                    self._state = CircuitState.OPEN
                else:
                    logger.warning(
                        "Circuit breaker for '%s' recorded failure %d/%d: %s",
                        self.service_name,
                        self._failure_count,
                        self.failure_threshold,
                        e,
                    )

            raise

    def get_state(self) -> CircuitState:
        """Get current circuit state."""
        return self._state

    def get_failure_count(self) -> int:
        """Get current failure count."""
        return self._failure_count

    def reset(self) -> None:
        """Manually reset the circuit breaker to CLOSED state."""
        async def _reset():
            async with self._lock:
                self._state = CircuitState.CLOSED
                self._failure_count = 0
                self._last_failure_time = 0.0
                logger.info("Circuit breaker for '%s' manually reset", self.service_name)

        # Run synchronously
        try:
            asyncio.get_event_loop().run_until_complete(_reset())
        except RuntimeError:
            # No event loop, just reset directly
            self._state = CircuitState.CLOSED
            self._failure_count = 0
            self._last_failure_time = 0.0
            logger.info("Circuit breaker for '%s' manually reset", self.service_name)


# Global circuit breaker instances
_circuit_breakers: dict[str, CircuitBreaker] = {}


def get_circuit_breaker(
    service_name: str,
    failure_threshold: int = 5,
    recovery_timeout: float = 60.0,
    expected_exception: type[Exception] | tuple[type[Exception], ...] = Exception,
) -> CircuitBreaker:
    """Get or create a circuit breaker for a service.

    Args:
        service_name: Name of the service
        failure_threshold: Number of failures before opening
        recovery_timeout: Seconds before trying again
        expected_exception: Exception types that count as failures

    Returns:
        CircuitBreaker instance
    """
    if service_name not in _circuit_breakers:
        _circuit_breakers[service_name] = CircuitBreaker(
            service_name=service_name,
            failure_threshold=failure_threshold,
            recovery_timeout=recovery_timeout,
            expected_exception=expected_exception,
        )
    return _circuit_breakers[service_name]


def with_circuit_breaker(
    service_name: str,
    failure_threshold: int = 5,
    recovery_timeout: float = 60.0,
    expected_exception: type[Exception] | tuple[type[Exception], ...] = Exception,
):
    """Decorator to apply circuit breaker protection to a function.

    Args:
        service_name: Name of the service being called
        failure_threshold: Number of failures before opening circuit
        recovery_timeout: Seconds before trying again
        expected_exception: Exception types that count as failures

    Example:
        ```python
        @with_circuit_breaker("opensearch", failure_threshold=3, recovery_timeout=30.0)
        async def search_opensearch(query: str):
            # ... search logic
        ```
    """

    def decorator(func: Callable[P, T]) -> Callable[P, T]:
        breaker = get_circuit_breaker(
            service_name=service_name,
            failure_threshold=failure_threshold,
            recovery_timeout=recovery_timeout,
            expected_exception=expected_exception,
        )

        @wraps(func)
        async def async_wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
            return await breaker.call(func, *args, **kwargs)

        @wraps(func)
        def sync_wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
            # For sync functions, we need to run in an event loop
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    # If we're already in an async context, raise error
                    raise RuntimeError(
                        "Cannot use circuit breaker with sync function in async context. "
                        "Make the function async."
                    )
                return loop.run_until_complete(breaker.call(func, *args, **kwargs))
            except RuntimeError:
                # No event loop, create one
                return asyncio.run(breaker.call(func, *args, **kwargs))

        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper

    return decorator
