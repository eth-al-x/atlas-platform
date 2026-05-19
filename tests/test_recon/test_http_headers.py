"""
Tests for the HTTP headers recon tool.
Uses respx to mock httpx requests so tests don't hit real websites.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from atlas.core.config import AtlasConfig
from atlas.recon.http_headers import HTTPHeadersReconTool


@pytest.fixture
def tool():
    """Create an HTTP headers recon tool with default config."""
    return HTTPHeadersReconTool(AtlasConfig())


class TestHTTPHeadersReconTool:

    # ── Basic response handling ──────────────────────────────

    @respx.mock
    def test_captures_status_code(self, tool):
        """Status code should appear in the result data."""
        respx.get("https://example.com").mock(
            return_value=httpx.Response(200, headers={"server": "nginx"})
        )

        result = tool.run("example.com")
        assert result.data["status_code"] == 200

    @respx.mock
    def test_captures_server_header(self, tool):
        """Server header should be surfaced in the top-level summary."""
        respx.get("https://example.com").mock(
            return_value=httpx.Response(200, headers={"server": "Apache/2.4.41"})
        )

        result = tool.run("example.com")
        assert result.data["server"] == "Apache/2.4.41"

    @respx.mock
    def test_missing_server_header(self, tool):
        """Missing server header should be reported as 'not disclosed'."""
        respx.get("https://example.com").mock(
            return_value=httpx.Response(200, headers={})
        )

        result = tool.run("example.com")
        assert result.data["server"] == "not disclosed"

    # ── Security header analysis ────────────────────────────

    @respx.mock
    def test_all_security_headers_present_strong_rating(self, tool):
        """A site with all 6 security headers should be rated Strong."""
        respx.get("https://example.com").mock(
            return_value=httpx.Response(200, headers={
                "strict-transport-security": "max-age=31536000",
                "content-security-policy": "default-src 'self'",
                "x-frame-options": "DENY",
                "x-content-type-options": "nosniff",
                "referrer-policy": "no-referrer",
                "permissions-policy": "geolocation=()",
            })
        )

        result = tool.run("example.com")
        security = result.data["security"]

        assert security["rating"] == "Strong"
        assert security["score_percentage"] == 100
        assert security["score"] == "6/6"

    @respx.mock
    def test_no_security_headers_weak_rating(self, tool):
        """A site with zero security headers should be rated Weak."""
        respx.get("https://example.com").mock(
            return_value=httpx.Response(200, headers={"content-type": "text/html"})
        )

        result = tool.run("example.com")
        security = result.data["security"]

        assert security["rating"] == "Weak"
        assert security["score_percentage"] == 0

    @respx.mock
    def test_partial_security_headers_moderate_rating(self, tool):
        """3 out of 6 security headers should rate Moderate."""
        respx.get("https://example.com").mock(
            return_value=httpx.Response(200, headers={
                "strict-transport-security": "max-age=31536000",
                "x-frame-options": "DENY",
                "x-content-type-options": "nosniff",
            })
        )

        result = tool.run("example.com")
        security = result.data["security"]

        assert security["score"] == "3/6"
        assert security["rating"] == "Moderate"

    @respx.mock
    def test_per_header_presence_reported(self, tool):
        """Each individual security header should have a presence flag."""
        respx.get("https://example.com").mock(
            return_value=httpx.Response(200, headers={
                "strict-transport-security": "max-age=31536000",
            })
        )

        result = tool.run("example.com")
        headers = result.data["security"]["headers"]

        assert headers["strict-transport-security"]["present"] is True
        assert headers["content-security-policy"]["present"] is False

    # ── Header case insensitivity ────────────────────────────

    @respx.mock
    def test_header_case_insensitive(self, tool):
        """HTTP headers are case-insensitive; security checks should reflect that."""
        # Mix of cases to verify normalization
        respx.get("https://example.com").mock(
            return_value=httpx.Response(200, headers={
                "Strict-Transport-Security": "max-age=31536000",
                "CONTENT-SECURITY-POLICY": "default-src 'self'",
            })
        )

        result = tool.run("example.com")
        headers = result.data["security"]["headers"]

        assert headers["strict-transport-security"]["present"] is True
        assert headers["content-security-policy"]["present"] is True

    # ── Error handling ──────────────────────────────────────

    @respx.mock
    def test_timeout_captured_as_error(self, tool):
        """A connection timeout should produce a result with an error message."""
        respx.get("https://example.com").mock(
            side_effect=httpx.TimeoutException("timed out")
        )

        result = tool.run("example.com")
        assert result.error is not None
        assert "timed out" in result.error.lower()
