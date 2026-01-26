"""
Standardized error response system.

Provides consistent error responses across all API endpoints.
"""
import uuid
from typing import Any, Dict, Optional

from fastapi import HTTPException, Request, status
from fastapi.responses import JSONResponse


class ErrorCode:
    """Standard error codes."""

    # Validation errors
    VALIDATION_ERROR = "VALIDATION_ERROR"
    INVALID_INPUT = "INVALID_INPUT"
    MISSING_FIELD = "MISSING_FIELD"

    # Authentication/Authorization
    UNAUTHORIZED = "UNAUTHORIZED"
    FORBIDDEN = "FORBIDDEN"
    INVALID_TOKEN = "INVALID_TOKEN"
    TOKEN_EXPIRED = "TOKEN_EXPIRED"

    # Resource errors
    NOT_FOUND = "NOT_FOUND"
    ALREADY_EXISTS = "ALREADY_EXISTS"
    CONFLICT = "CONFLICT"

    # Business logic errors
    BUSINESS_RULE_VIOLATION = "BUSINESS_RULE_VIOLATION"
    OPERATION_NOT_ALLOWED = "OPERATION_NOT_ALLOWED"

    # External service errors
    EXTERNAL_SERVICE_ERROR = "EXTERNAL_SERVICE_ERROR"
    EXTERNAL_SERVICE_UNAVAILABLE = "EXTERNAL_SERVICE_UNAVAILABLE"

    # System errors
    INTERNAL_ERROR = "INTERNAL_ERROR"
    SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE"


class ErrorResponse:
    """Standard error response format."""

    @staticmethod
    def create(
        code: str,
        message: str,
        status_code: int = 500,
        details: Optional[Dict[str, Any]] = None,
        request_id: Optional[str] = None,
    ) -> JSONResponse:
        """
        Create a standardized error response.

        Args:
            code: Machine-readable error code
            message: Human-readable error message
            status_code: HTTP status code
            details: Additional error details (optional)
            request_id: Request correlation ID (optional)

        Returns:
            JSONResponse with standard error format
        """
        error_data: Dict[str, Any] = {
            "error": {
                "code": code,
                "message": message,
            }
        }

        if details:
            error_data["error"]["details"] = details

        if request_id:
            error_data["error"]["request_id"] = request_id

        return JSONResponse(status_code=status_code, content=error_data)


class HTTPError(HTTPException):
    """
    Enhanced HTTPException with standard error response format.

    Usage:
        raise HTTPError(
            status_code=404,
            code=ErrorCode.NOT_FOUND,
            message="Rule not found",
            details={"rule_id": 123}
        )
    """

    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
        details: Optional[Dict[str, Any]] = None,
    ):
        """
        Initialize HTTPError.

        Args:
            status_code: HTTP status code
            code: Machine-readable error code
            message: Human-readable error message
            details: Additional error details (optional)
        """
        self.code = code
        self.message = message
        self.details = details
        super().__init__(status_code=status_code, detail=message)


async def http_error_handler(request: Request, exc: HTTPError) -> JSONResponse:
    """
    Handle HTTPError exceptions and return standardized error response.

    This should be added to FastAPI exception handlers.
    """
    # Get request ID from state if available
    request_id = getattr(request.state, "request_id", str(uuid.uuid4()))

    return ErrorResponse.create(
        code=exc.code,
        message=exc.message,
        status_code=exc.status_code,
        details=exc.details,
        request_id=request_id,
    )


# Convenience functions for common errors

def not_found(resource: str, details: Optional[Dict[str, Any]] = None) -> HTTPError:
    """Create a 404 NOT_FOUND error."""
    return HTTPError(
        status_code=status.HTTP_404_NOT_FOUND,
        code=ErrorCode.NOT_FOUND,
        message=f"{resource} not found",
        details=details,
    )


def unauthorized(message: str = "Unauthorized", details: Optional[Dict[str, Any]] = None) -> HTTPError:
    """Create a 401 UNAUTHORIZED error."""
    return HTTPError(
        status_code=status.HTTP_401_UNAUTHORIZED,
        code=ErrorCode.UNAUTHORIZED,
        message=message,
        details=details,
    )


def forbidden(message: str = "Forbidden", details: Optional[Dict[str, Any]] = None) -> HTTPError:
    """Create a 403 FORBIDDEN error."""
    return HTTPError(
        status_code=status.HTTP_403_FORBIDDEN,
        code=ErrorCode.FORBIDDEN,
        message=message,
        details=details,
    )


def validation_error(message: str, details: Optional[Dict[str, Any]] = None) -> HTTPError:
    """Create a 400 VALIDATION_ERROR error."""
    return HTTPError(
        status_code=status.HTTP_400_BAD_REQUEST,
        code=ErrorCode.VALIDATION_ERROR,
        message=message,
        details=details,
    )


def conflict(message: str, details: Optional[Dict[str, Any]] = None) -> HTTPError:
    """Create a 409 CONFLICT error."""
    return HTTPError(
        status_code=status.HTTP_409_CONFLICT,
        code=ErrorCode.CONFLICT,
        message=message,
        details=details,
    )


def internal_error(message: str = "Internal server error", details: Optional[Dict[str, Any]] = None) -> HTTPError:
    """Create a 500 INTERNAL_ERROR error."""
    return HTTPError(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        code=ErrorCode.INTERNAL_ERROR,
        message=message,
        details=details,
    )
