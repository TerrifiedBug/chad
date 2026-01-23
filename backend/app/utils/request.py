"""Request utility functions."""

from fastapi import Request


def get_client_ip(request: Request) -> str:
    """
    Extract real client IP, respecting proxy headers.

    Checks headers in order:
    1. X-Forwarded-For (may contain chain: "client, proxy1, proxy2")
    2. X-Real-IP (single IP from nginx)
    3. Direct connection IP
    """
    # X-Forwarded-For may contain chain of IPs
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        # First IP in chain is the original client
        return forwarded.split(",")[0].strip()

    # X-Real-IP is typically set by nginx
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()

    # Fallback to direct connection
    if request.client:
        return request.client.host

    return "unknown"
