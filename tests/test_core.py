"""
Tests for core domain extraction and pipeline structure.
Run with: pytest tests/ -v
"""

import pytest
from atlas.core.domain import extract_domain, normalize_url
from atlas.core.models import ScanRequest, TierResult, Verdict


class TestExtractDomain:
    """Domain extraction should handle a wide range of URL formats."""

    def test_basic_url(self):
        assert extract_domain("https://example.com/path") == "example.com"

    def test_strips_www(self):
        assert extract_domain("https://www.example.com") == "example.com"

    def test_strips_mobile_prefix(self):
        assert extract_domain("https://m.example.com") == "example.com"

    def test_strips_mail_prefix(self):
        assert extract_domain("https://mail.google.com") == "google.com"

    def test_no_scheme(self):
        assert extract_domain("example.com") == "example.com"

    def test_with_port(self):
        assert extract_domain("https://example.com:8080/path") == "example.com"

    def test_with_userinfo(self):
        assert extract_domain("https://user:pass@evil.com") == "evil.com"

    def test_trailing_dot(self):
        assert extract_domain("https://example.com.") == "example.com"

    def test_case_insensitive(self):
        assert extract_domain("https://EXAMPLE.COM") == "example.com"

    def test_subdomain_preserved(self):
        """Non-common subdomains should be kept."""
        assert extract_domain("https://api.example.com") == "api.example.com"

    def test_complex_url(self):
        assert extract_domain("https://www.example.com:443/path?q=1&r=2#frag") == "example.com"


class TestNormalizeUrl:
    def test_adds_scheme(self):
        assert normalize_url("example.com") == "https://example.com"

    def test_preserves_existing_https(self):
        assert normalize_url("https://example.com") == "https://example.com"

    def test_preserves_existing_http(self):
        assert normalize_url("http://example.com") == "http://example.com"

    def test_strips_whitespace(self):
        assert normalize_url("  example.com  ") == "https://example.com"


class TestTierResult:
    def test_passed_when_not_flagged(self):
        result = TierResult(tier_name="test", flagged=False)
        assert result.passed is True

    def test_not_passed_when_flagged(self):
        result = TierResult(tier_name="test", flagged=True)
        assert result.passed is False

    def test_not_passed_on_error(self):
        result = TierResult(tier_name="test", flagged=False, error="timeout")
        assert result.passed is False
