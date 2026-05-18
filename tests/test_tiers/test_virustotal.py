"""
Tests for the virustotal tier.
Uses respx to mock HTTP calls so tests don't hit the real API.
"""

import pytest
import respx
import httpx

from atlas.core.config import AtlasConfig
from atlas.tiers.virustotal import VirusTotalTier

@pytest.fixture
def tier():
    """Create a VirusTotal Tier with a fake API key."""
    config = AtlasConfig()
    vt = VirusTotalTier(config)
    vt.api_key = "fake-key-for-testing"
    return vt


class TestVirusTotalTier:

    def test_no_api_key_returns_error(self):
        """Tier should gracefully report missing API key."""
        config = AtlasConfig()
        vt = VirusTotalTier(config)
        vt.api_key = ""

        result = vt.check("example.com", url="https://example.com")
        assert result.flagged is False
        assert "API" in (result.error or "")

    @respx.mock
    def test_clean_url_not_flagged(self, tier):
        """A URL with zero malicious engines should not be flagged."""
        # Mock the submission endpoint
        respx.post("https://www.virustotal.com/api/v3/urls").mock(
            return_value=httpx.Response(200, json={
                "data": {"id": "test-analysis-id"}
            })
        )

        # Mock the analysis endpoint - return completed immediately
        respx.get("https://www.virustotal.com/api/v3/analyses/test-analysis-id").mock(
            return_value=httpx.Response(200, json={
                "data": {"attributes": {
                    "status": "completed",
                    "stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "harmless": 65,
                        "undetected": 5,
                    }
                }}
            })
        )
        result = tier.check("example.com", url="https://example.com")
        assert result.flagged is False
        assert result.details["danger_score_percentage"] == 0.0

    @respx.mock
    def test_malicious_url_flagged(self, tier):
        """A URL flagged by multiple engines should be flagged with high confidence."""
        respx.post("https://www.virustotal.com/api/v3/urls").mock(
            return_value=httpx.Response(200, json={
                "data": {"id": "test-analysis-id"}
            })
        )

        respx.get("https://www.virustotal.com/api/v3/analyses/test-analysis-id").mock(
            return_value=httpx.Response(200, json={
                "data": {"attributes": {
                    "status": "completed",
                    "stats": {
                        "malicious": 15,
                        "suspicious": 3,
                        "harmless": 45,
                        "undetected": 7,
                    }
                }}
            })
        )

        result = tier.check("evil.com", url="https://evil.com")
        assert result.flagged is True
        assert result.details["malicious_engines"] == 15
        assert result.details["danger_score_percentage"] > 10.0

    @respx.mock
    def test_rate_limit_retries(self, tier):
        """Tier should retry on 429 before giving up."""
        # Make the config fast for testing
        tier.retry_wait = 0 # Don't wait in tests
        tier.max_retries = 2

        # Both attempts return 429
        respx.post("https://www.virustotal.com/api/v3/urls").mock(
            return_value=httpx.Response(429)
        )

        result = tier.check("example.com", url="https://example.com")
        assert result.flagged is False
        assert result.error is not None