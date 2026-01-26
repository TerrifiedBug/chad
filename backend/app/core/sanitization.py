"""
Input sanitization for security.

Provides HTML sanitization to prevent XSS attacks in user-generated content.
"""
import re
from typing import Optional

try:
    import nh3
    HAS_NH3 = True
except ImportError:
    HAS_NH3 = False


# Patterns for dangerous content
DANGEROUS_PATTERNS = [
    r'<script[^>]*>.*?</script>',  # Script tags
    r'javascript:',  # JavaScript protocol
    r'on\w+\s*=',  # Event handlers (onclick, onload, etc.)
    r'<iframe[^>]*>',  # Iframes
    r'<object[^>]*>',  # Objects
    r'<embed[^>]*>',  # Embeds
]

COMPILED_PATTERNS = [re.compile(pattern, re.IGNORECASE | re.DOTALL) for pattern in DANGEROUS_PATTERNS]


def sanitize_html(html: Optional[str], allow_tags: Optional[list[str]] = None) -> str:
    """
    Sanitize HTML to prevent XSS attacks.

    Args:
        html: HTML string to sanitize
        allow_tags: List of allowed HTML tags (default: basic formatting tags)

    Returns:
        Sanitized HTML string

    Examples:
        >>> sanitize_html("<p>Hello</p>")
        '<p>Hello</p>'
        >>> sanitize_html("<script>alert('xss')</script><p>Hello</p>")
        '<p>Hello</p>'
    """
    if not html:
        return ""

    # If nh3 is available, use it (preferred)
    if HAS_NH3:
        allowed_tags = allow_tags or [
            'p', 'br', 'strong', 'em', 'u', 'a',
            'ul', 'ol', 'li', 'code', 'pre',
            'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
            'blockquote', 'sub', 'sup'
        ]

        # Configure nh3
        # Allow safe tags and basic attributes
        return nh3.clean(
            html,
            tags=set(allowed_tags),
        )

    # Fallback: Use regex-based sanitization (less secure, use nh3!)
    sanitized = html
    for pattern in COMPILED_PATTERNS:
        sanitized = pattern.sub('', sanitized)

    return sanitized


def sanitize_text(text: Optional[str]) -> str:
    """
    Sanitize plain text (remove all HTML).

    Args:
        text: Text to sanitize

    Returns:
        Sanitized text with HTML removed
    """
    if not text:
        return ""

    # Remove all HTML tags
    clean_text = re.sub(r'<[^>]+>', '', text)

    # Decode HTML entities
    clean_text = clean_text.replace('&lt;', '<')
    clean_text = clean_text.replace('&gt;', '>')
    clean_text = clean_text.replace('&amp;', '&')
    clean_text = clean_text.replace('&quot;', '"')
    clean_text = clean_text.replace('&#39;', "'")

    return clean_text.strip()


def sanitize_markdown(markdown: Optional[str]) -> str:
    """
    Sanitize markdown content.

    Markdown will be converted to HTML and then sanitized.

    Args:
        markdown: Markdown string to sanitize

    Returns:
        Sanitized markdown (still in markdown format)
    """
    if not markdown:
        return ""

    # For now, just sanitize dangerous patterns
    # In production, you might want to convert markdown to HTML first,
    # then sanitize, then convert back

    sanitized = markdown

    # Remove HTML tags from markdown
    for pattern in COMPILED_PATTERNS:
        sanitized = pattern.sub('', sanitized)

    return sanitized


def check_for_xss(content: Optional[str]) -> list[str]:
    """
    Check content for potential XSS attacks.

    Args:
        content: Content to check

    Returns:
        List of detected XSS patterns (empty if safe)
    """
    if not content:
        return []

    detected = []

    for i, pattern in enumerate(COMPILED_PATTERNS):
        matches = pattern.findall(content)
        if matches:
            detected.append(f"Pattern {i}: {matches}")

    # Check for common XSS strings
    xss_strings = [
        '<script>',
        'javascript:',
        'onerror=',
        'onload=',
        'onclick=',
        'onmouseover=',
    ]

    content_lower = content.lower()
    for xss_str in xss_strings:
        if xss_str in content_lower:
            detected.append(f"Suspicious string: {xss_str}")

    return detected


def sanitize_user_input(
    value: Optional[str],
    field_type: str = "text"
) -> str:
    """
    Sanitize user input based on field type.

    Args:
        value: User input to sanitize
        field_type: Type of field (text, html, markdown)

    Returns:
        Sanitized value
    """
    if not value:
        return ""

    if field_type == "html":
        return sanitize_html(value)
    elif field_type == "markdown":
        return sanitize_markdown(value)
    else:  # text
        return sanitize_text(value)
