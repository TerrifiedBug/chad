"""
CSRF Protection Middleware for FastAPI.

Implements CSRF token validation for state-changing operations.
Since the app uses JWT authentication (Authorization header), CSRF risk is reduced,
but this provides defense-in-depth protection.

Uses Double Submit Cookie pattern with SameSite cookies and Origin/Referer validation.
"""

import secrets
import logging
from typing import Callable
from urllib.parse import urlparse

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.config import settings

logger = logging.getLogger(__name__)

# CSRF token length (bytes)
CSRF_TOKEN_LENGTH = 32

# CSRF token name for cookie and header
CSRF_COOKIE_NAME = "csrf_token"
CSRF_HEADER_NAME = "X-CSRF-Token"

# Safe methods that don't require CSRF protection
SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}


def generate_csrf_token() -> str:
    """Generate a secure random CSRF token."""
    return secrets.token_hex(CSRF_TOKEN_LENGTH)


def is_safe_origin(origin: str | None, referer: str | None, app_url: str | None, host: str | None = None) -> bool:
    """
    Validate that the Origin, Referer, or Host header is allowed.

    In development mode, allows localhost origins.
    In production, validates against configured APP_URL hostname.

    Args:
        origin: Origin header value
        referer: Referer header value
        app_url: Configured application URL from environment
        host: Host header value (direct request, for proxy scenarios)

    Returns:
        True if origin/referer/host is allowed, False otherwise
    """
    if not origin and not referer and not host:
        return False

    # Allow localhost in development mode
    if settings.DEBUG:
        allowed_origins = [
            "http://localhost:3000",
            "http://frontend:3000",
            "http://127.0.0.1:3000",
            "http://localhost:80",
            "http://127.0.0.1:80"
        ]
        if origin and origin in allowed_origins:
            return True
        if referer:
            if any(referer.startswith(o) for o in allowed_origins):
                return True
        if host:
            # Allow localhost host in DEBUG mode
            if host in ["localhost", "127.0.0.1", "frontend"]:
                return True

    # Production: validate against configured APP_URL
    if app_url:
        # Extract hostname from APP_URL (e.g., https://chad.terrifiedbug.com)
        expected_host = urlparse(app_url).hostname

        if not expected_host:
            logger.warning(f"Invalid APP_URL format: {app_url}")
            return False

        # Check origin header
        if origin:
            origin_host = urlparse(origin).hostname
            if origin_host == expected_host:
                return True

        # Check referer header as fallback
        if referer:
            referer_host = urlparse(referer).hostname
            if referer_host == expected_host:
                return True

        # Check host header (for reverse proxy scenarios)
        if host:
            if host == expected_host:
                return True

    return False


class CSRFMiddleware(BaseHTTPMiddleware):
    """
    CSRF Protection Middleware.

    Implements:
    1. Double Submit Cookie pattern - token in cookie must match token in header
    2. Origin/Referer/Host validation - ensures request comes from allowed source
    3. SameSite cookies - prevents CSRF from third-party sites (already configured in SessionMiddleware)
    4. Exempts safe methods (GET, HEAD, OPTIONS, TRACE)

    For API-first applications with JWT authentication, CSRF protection is
    defense-in-depth. The primary protection is JWT tokens in Authorization header.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Process request through CSRF middleware.

        For safe methods (GET, HEAD, OPTIONS, TRACE):
            - Generate and set CSRF cookie if not present

        For state-changing methods (POST, PUT, PATCH, DELETE):
            - Validate CSRF token from header matches cookie
            - Validate Origin/Referer/Host headers
        """
        # For API requests with JWT authentication, CSRF is less critical
        # but we still protect against cross-site attacks

        if request.method in SAFE_METHODS:
            # Safe methods - ensure CSRF token exists for later use
            csrf_token = request.cookies.get(CSRF_COOKIE_NAME)

            if not csrf_token:
                # Generate new token and set it
                csrf_token = generate_csrf_token()
                response = await call_next(request)

                # Set CSRF token as cookie (HttpOnly, SameSite=Strict)
                response.set_cookie(
                    key=CSRF_COOKIE_NAME,
                    value=csrf_token,
                    httponly=True,
                    secure=not settings.DEBUG,  # HTTPS in production
                    samesite="strict",  # Strict CSRF protection
                    max_age=3600,  # 1 hour
                    path="/",
                )

                # Add CSRF token to response headers for JavaScript access
                response.headers[CSRF_HEADER_NAME] = csrf_token

                return response

            # Token exists, just pass through
            response = await call_next(request)

            # Add CSRF token to response headers for JavaScript access
            if csrf_token:
                response.headers[CSRF_HEADER_NAME] = csrf_token

            return response

        # State-changing methods - validate CSRF
        # For API routes with JWT, we can optionally skip CSRF if Authorization header is present
        auth_header = request.headers.get("authorization")

        if auth_header and auth_header.startswith("Bearer "):
            # JWT authenticated request - CSRF protection is less critical
            # but we still validate origin/referer for defense-in-depth
            origin = request.headers.get("origin")
            referer = request.headers.get("referer")
            host = request.headers.get("host")

            if not is_safe_origin(origin, referer, settings.APP_URL, host):
                logger.warning(
                    f"CSRF: Unsafe origin/referer/host from authenticated request: "
                    f"origin={origin}, referer={referer}, host={host}, expected={settings.APP_URL}"
                )
                # For API requests, we'll log but not block (can be configured to block)
                # In production, you may want to reject these requests

            response = await call_next(request)
            return response

        # No JWT token - enforce CSRF protection
        # Get token from cookie
        csrf_cookie = request.cookies.get(CSRF_COOKIE_NAME)

        if not csrf_cookie:
            logger.warning(f"CSRF: Missing cookie for state-changing request: {request.url}")
            response = JSONResponse(
                {"detail": "CSRF token missing. Please refresh the page and try again."},
                status_code=403
            )
            return response

        # Get token from header
        csrf_header = request.headers.get(CSRF_HEADER_NAME)

        if not csrf_header:
            logger.warning(f"CSRF: Missing header for state-changing request: {request.url}")
            response = JSONResponse(
                {"detail": "CSRF token required. Please include X-CSRF-Token header."},
                status_code=403
            )
            return response

        # Validate tokens match
        if not secrets.compare_digest(csrf_cookie.encode(), csrf_header.encode()):
            logger.warning(f"CSRF: Token mismatch for state-changing request: {request.url}")
            response = JSONResponse(
                {"detail": "CSRF token validation failed. Please refresh the page and try again."},
                status_code=403
            )
            return response

        # Validate origin/referer/host
        origin = request.headers.get("origin")
        referer = request.headers.get("referer")
        host = request.headers.get("host")

        if not is_safe_origin(origin, referer, settings.APP_URL, host):
            logger.warning(
                f"CSRF: Unsafe origin/referer/host: origin={origin}, referer={referer}, host={host}, "
                f"expected={settings.APP_URL}, url={request.url}"
            )
            response = JSONResponse(
                {"detail": "Cross-site request not allowed."},
                status_code=403
            )
            return response

        # All checks passed
        response = await call_next(request)
        return response
