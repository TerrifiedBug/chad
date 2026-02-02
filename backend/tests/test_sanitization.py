"""
Tests for input sanitization.
"""

from app.core.sanitization import (
    check_for_xss,
    sanitize_html,
    sanitize_markdown,
    sanitize_text,
    sanitize_user_input,
)


class TestSanitizeHtml:
    """Tests for HTML sanitization."""

    def test_removes_script_tags(self):
        """Script tags should be removed."""
        html = "<p>Hello</p><script>alert('xss')</script>"
        result = sanitize_html(html)
        assert "<script>" not in result
        assert "alert" not in result
        assert "<p>Hello</p>" in result or "Hello" in result

    def test_removes_javascript_protocol(self):
        """JavaScript: protocol should be removed."""
        html = '<a href="javascript:alert(\'xss\')">Click</a>'
        result = sanitize_html(html)
        assert "javascript:" not in result.lower()

    def test_removes_event_handlers(self):
        """Event handlers should be removed."""
        html = '<p onclick="alert(\'xss\')">Click</p>'
        result = sanitize_html(html)
        assert "onclick" not in result.lower()

    def test_allows_safe_html(self):
        """Safe HTML tags should be preserved."""
        html = "<p>Hello <strong>world</strong></p>"
        result = sanitize_html(html)
        assert "<p>" in result
        assert "<strong>" in result

    def test_allows_links(self):
        """Safe links should be preserved."""
        html = '<a href="https://example.com">Link</a>'
        result = sanitize_html(html)
        assert "<a>" in result or 'href=' in result

    def test_removes_iframes(self):
        """Iframes should be removed."""
        html = '<iframe src="https://evil.com"></iframe>'
        result = sanitize_html(html)
        assert "<iframe" not in result.lower()

    def test_empty_input(self):
        """Empty input should return empty string."""
        assert sanitize_html(None) == ""
        assert sanitize_html("") == ""


class TestSanitizeText:
    """Tests for text sanitization."""

    def test_removes_all_html(self):
        """All HTML tags should be removed."""
        text = "<p>Hello <strong>world</strong></p>"
        result = sanitize_text(text)
        assert "<" not in result
        assert ">" not in result
        assert "Hello world" in result

    def test_preserves_plain_text(self):
        """Plain text should be unchanged."""
        text = "Hello world!"
        result = sanitize_text(text)
        assert result == "Hello world!"

    def test_empty_input(self):
        """Empty input should return empty string."""
        assert sanitize_text(None) == ""
        assert sanitize_text("") == ""


class TestSanitizeMarkdown:
    """Tests for markdown sanitization."""

    def test_removes_script_tags(self):
        """Script tags should be removed from markdown."""
        markdown = "Hello\n\n<script>alert('xss')</script>"
        result = sanitize_markdown(markdown)
        assert "<script>" not in result

    def test_removes_javascript_protocol(self):
        """JavaScript: protocol should be removed."""
        markdown = "[Link](javascript:alert('xss'))"
        result = sanitize_markdown(markdown)
        assert "javascript:" not in result.lower()

    def test_preserves_safe_markdown(self):
        """Safe markdown should be preserved."""
        markdown = "## Header\n\nHello **world**"
        result = sanitize_markdown(markdown)
        assert "## Header" in result
        assert "**world**" in result

    def test_empty_input(self):
        """Empty input should return empty string."""
        assert sanitize_markdown(None) == ""
        assert sanitize_markdown("") == ""


class TestCheckForXss:
    """Tests for XSS detection."""

    def test_detects_script_tags(self):
        """Script tags should be detected."""
        content = "<p>Hello</p><script>alert('xss')</script>"
        result = check_for_xss(content)
        assert len(result) > 0
        assert any("script" in r.lower() for r in result)

    def test_detects_javascript_protocol(self):
        """JavaScript: protocol should be detected."""
        content = '<a href="javascript:alert(\'xss\')">Click</a>'
        result = check_for_xss(content)
        assert len(result) > 0

    def test_detects_event_handlers(self):
        """Event handlers should be detected."""
        content = '<p onclick="alert(\'xss\')">Click</p>'
        result = check_for_xss(content)
        assert len(result) > 0

    def test_safe_content_passes(self):
        """Safe content should not be flagged."""
        content = "<p>Hello <strong>world</strong></p>"
        result = check_for_xss(content)
        assert len(result) == 0

    def test_empty_input(self):
        """Empty input should return empty list."""
        assert check_for_xss(None) == []
        assert check_for_xss("") == []


class TestSanitizeUserInput:
    """Tests for user input sanitization."""

    def test_sanitizes_html_fields(self):
        """HTML fields should be sanitized."""
        html = "<p>Hello</p><script>alert('xss')</script>"
        result = sanitize_user_input(html, field_type="html")
        assert "<script>" not in result

    def test_sanitizes_markdown_fields(self):
        """Markdown fields should be sanitized."""
        markdown = "# Hello\n\n<script>alert('xss')</script>"
        result = sanitize_user_input(markdown, field_type="markdown")
        assert "<script>" not in result

    def test_sanitizes_text_fields(self):
        """Text fields should have HTML removed."""
        text = "<p>Hello <strong>world</strong></p>"
        result = sanitize_user_input(text, field_type="text")
        assert "<" not in result

    def test_default_field_type(self):
        """Default field type should be 'text'."""
        html = "<p>Hello</p>"
        result = sanitize_user_input(html)
        assert "<" not in result

    def test_empty_input(self):
        """Empty input should return empty string."""
        assert sanitize_user_input(None) == ""
        assert sanitize_user_input("") == ""


class TestNh3LibrarySmokeTest:
    """
    Smoke test to catch nh3 library API breaking changes.

    This test ensures that the nh3 library integration works correctly
    and will catch breaking API changes in future dependency updates.
    Run this after updating nh3 to verify compatibility.
    """

    def test_nh3_basic_functionality(self):
        """
        Test that nh3.clean() works with current API.

        This is a canary test - if this fails after a dependency update,
        it means nh3's API has changed and needs code fixes.
        """
        # Test basic HTML sanitization
        result = sanitize_html("<p>Hello</p><script>alert('xss')</script>")

        # Verify safe content is preserved
        assert "<p>Hello</p>" in result or "Hello" in result

        # Verify dangerous content is removed
        assert "<script>" not in result
        assert "alert" not in result

    def test_nh3_with_allowed_tags(self):
        """Test that nh3 respects the allowed tags configuration."""
        # Test with various safe tags
        html = "<h1>Title</h1><p>Paragraph</p><strong>Bold</strong><code>Code</code>"
        result = sanitize_html(html)

        # All these tags should be preserved
        assert "<h1>" in result
        assert "<p>" in result
        assert "<strong>" in result
        assert "<code>" in result
