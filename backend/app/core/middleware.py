"""Custom middleware for request validation and error handling."""

import logging
from typing import Callable

from fastapi import Request, Response, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

logger = logging.getLogger(__name__)


class RequestValidationMiddleware(BaseHTTPMiddleware):
    """Middleware for request validation and security checks.

    Enforces:
    - Request size limits
    - Content-Type validation for POST/PUT/PATCH
    - Request ID generation
    """

    def __init__(
        self,
        app: ASGIApp,
        max_request_size: int = 10 * 1024 * 1024,  # 10 MB default
        enforce_content_type: bool = True,
    ) -> None:
        super().__init__(app)
        self.max_request_size = max_request_size
        self.enforce_content_type = enforce_content_type

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request and apply validation."""
        # Generate request ID for tracing
        request_id = request.headers.get("X-Request-ID", "")
        if not request_id:
            import uuid
            request_id = str(uuid.uuid4())

        # Add request ID to request state for use in endpoints
        request.state.request_id = request_id

        # Check content-length for size limits
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                size = int(content_length)
                if size > self.max_request_size:
                    logger.warning(
                        f"Request too large: {size} bytes from {request.client.host}"
                    )
                    return JSONResponse(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        content={
                            "detail": f"Request too large. Maximum size is {self.max_request_size} bytes",
                            "error_code": "REQUEST_TOO_LARGE",
                            "request_id": request_id,
                        },
                    )
            except ValueError:
                pass

        # Validate Content-Type for state-changing methods
        if self.enforce_content_type and request.method in {"POST", "PUT", "PATCH"}:
            # Skip validation for WebSocket upgrade requests
            if request.url.path != "/api/ws" and not request.url.path.startswith("/api/ws/"):
                content_type = request.headers.get("content-type", "")
                if not content_type or not content_type.startswith(
                    ("application/json", "multipart/form-data", "application/x-www-form-urlencoded")
                ):
                    logger.warning(
                        f"Invalid Content-Type from {request.client.host}: {content_type}"
                    )
                    return JSONResponse(
                        status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                        content={
                            "detail": "Content-Type must be application/json or multipart/form-data",
                            "error_code": "INVALID_CONTENT_TYPE",
                            "request_id": request_id,
                        },
                    )

        # Process request
        try:
            response = await call_next(request)
            # Add request ID to response headers
            response.headers["X-Request-ID"] = request_id
            return response
        except Exception as e:
            logger.exception(f"Unhandled exception during request processing: {e}")
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={
                    "detail": "Internal server error",
                    "error_code": "INTERNAL_ERROR",
                    "request_id": request_id,
                },
            )


class ErrorResponseMiddleware(BaseHTTPMiddleware):
    """Middleware to standardize error responses.

    Catches exceptions and returns consistent error response format.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request and handle errors."""
        try:
            return await call_next(request)
        except Exception as e:
            # Get request ID if available
            request_id = getattr(request.state, "request_id", "unknown")

            # Log the error
            logger.exception(f"Request error: {request.method} {request.url.path}")

            # Return standardized error response
            status_code = status.HTTP_500_INTERNAL_SERVER_ERROR

            # Handle specific exceptions
            from fastapi import HTTPException
            from fastapi.exceptions import RequestValidationError
            from sqlalchemy.exc import IntegrityError, OperationalError

            if isinstance(e, HTTPException):
                status_code = e.status_code
                detail = str(e.detail)
            elif isinstance(e, RequestValidationError):
                status_code = status.HTTP_422_UNPROCESSABLE_ENTITY
                detail = "Validation error"
                logger.warning(f"Validation error: {e.errors()}")
            elif isinstance(e, IntegrityError):
                status_code = status.HTTP_409_CONFLICT
                detail = "Data integrity error (duplicate or foreign key violation)"
            elif isinstance(e, OperationalError):
                status_code = status.HTTP_503_SERVICE_UNAVAILABLE
                detail = "Database operation failed"
            else:
                detail = "An unexpected error occurred"

            return JSONResponse(
                content={
                    "detail": detail,
                    "error_code": getattr(e, "error_code", type(e).__name__.upper()),
                    "request_id": request_id,
                },
                status_code=status_code,
            )
