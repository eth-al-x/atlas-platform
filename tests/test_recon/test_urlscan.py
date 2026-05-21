"""
Tests for the urlscan.io recon tool.

Uses respx to mock the urlscan API. Monkeypatches time.sleep so polling
tests don't actually wait the full 30+ seconds.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from atlas.core.config import AtlasConfig
from atlas.recon.urlscan import URLScanReconTool, URLSCAN_RESULT_URL, URLSCAN_SUBMIT_URL


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    """Disable real sleep so polling tests run instantly."""
    monkeypatch.setattr("atlas.recon.urlscan.time.sleep", lambda x: None)


@pytest.fixture
def tool():
    """Create a urlscan tool with a fake API key."""
    config = AtlasConfig()
    t = URLScanReconTool(config)
    t.api_key = "fake-urlscan-key"
    return t


# A full urlscan result JSON, trimmed to the fields ATLAS actually extracts
COMPLETE_RESULT = {
    "task": {
        "uuid": "test-uuid-12345",
        "url": "https://example.com/",
        "reportURL": "https://urlscan.io/result/test-uuid-12345/",
        "screenshotURL": "https://urlscan.io/screenshots/test-uuid-12345.png",
    },
    "page": {
        "ip": "93.184.216.34",
        "country": "US",
        "server": "ECS (dcb/7EA2)",
        "domain": "example.com",
        "umbrellaRank": 50,
    },
    "verdicts": {
        "overall": {
            "malicious": False,
            "score": 0,
            "tags": [],
        }
    },
    "stats": {
        "uniqIPs": 1,
        "uniqCountries": 1,
        "uniqDomains": 1,
        "requests": 5,
        "malicious": 0,
    },
    "lists": {
        "ips": ["93.184.216.34"],
        "domains": ["example.com"],
    },
}


MALICIOUS_RESULT = {
    **COMPLETE_RESULT,
    "verdicts": {
        "overall": {
            "malicious": True,
            "score": 100,
            "tags": ["phishing", "credentials"],
        }
    },
    "stats": {
        "uniqIPs": 12,
        "uniqCountries": 4,
        "uniqDomains": 8,
        "requests": 47,
        "malicious": 3,
    },
}


class TestURLScanReconTool:

    # ── API key validation ───────────────────────────────────

    def test_no_api_key_returns_error(self):
        """Missing API key should produce an error result, not crash."""
        config = AtlasConfig()
        t = URLScanReconTool(config)
        t.api_key = ""

        result = t.run("https://example.com")
        assert result.flagged is False if hasattr(result, "flagged") else True
        assert result.error is not None
        assert "URLSCAN_API_KEY" in result.error

    # ── Submission failures ──────────────────────────────────

    @respx.mock
    def test_invalid_api_key(self, tool):
        """401 from urlscan should produce a clear error."""
        respx.post(URLSCAN_SUBMIT_URL).mock(return_value=httpx.Response(401))

        result = tool.run("https://example.com")
        assert result.error is not None
        assert "invalid" in result.error.lower()

    @respx.mock
    def test_url_rejected(self, tool):
        """400 from urlscan (e.g., private IP) should be captured."""
        respx.post(URLSCAN_SUBMIT_URL).mock(
            return_value=httpx.Response(400, json={
                "message": "DNS Error",
                "description": "URL points to private IP",
            })
        )

        result = tool.run("https://example.com")
        assert result.error is not None
        assert "rejected" in result.error.lower()

    @respx.mock
    def test_rate_limit(self, tool):
        """429 from urlscan should produce a rate-limit error."""
        respx.post(URLSCAN_SUBMIT_URL).mock(return_value=httpx.Response(429))

        result = tool.run("https://example.com")
        assert result.error is not None
        assert "rate limit" in result.error.lower()

    # ── Successful submission and polling ────────────────────

    @respx.mock
    def test_clean_url_scan(self, tool):
        """A clean URL scan should return verdict=not malicious with score 0."""
        # Submit returns a UUID
        respx.post(URLSCAN_SUBMIT_URL).mock(
            return_value=httpx.Response(200, json={"uuid": "test-uuid-12345"})
        )
        # Polling returns the completed result
        respx.get(URLSCAN_RESULT_URL.format(uuid="test-uuid-12345")).mock(
            return_value=httpx.Response(200, json=COMPLETE_RESULT)
        )

        result = tool.run("https://example.com")

        assert result.error is None
        assert result.data["malicious"] is False
        assert result.data["score"] == 0
        assert result.data["uuid"] == "test-uuid-12345"

    @respx.mock
    def test_malicious_url_scan(self, tool):
        """A malicious verdict should surface with the tags and high score."""
        respx.post(URLSCAN_SUBMIT_URL).mock(
            return_value=httpx.Response(200, json={"uuid": "test-uuid-12345"})
        )
        respx.get(URLSCAN_RESULT_URL.format(uuid="test-uuid-12345")).mock(
            return_value=httpx.Response(200, json=MALICIOUS_RESULT)
        )

        result = tool.run("https://evil.com")

        assert result.error is None
        assert result.data["malicious"] is True
        assert result.data["score"] == 100
        assert "phishing" in result.data["tags"]
        assert result.data["stats"]["malicious_requests"] == 3

    # ── Polling behavior ─────────────────────────────────────

    @respx.mock
    def test_polling_eventually_succeeds(self, tool):
        """A scan that's not ready immediately should poll until it succeeds."""
        respx.post(URLSCAN_SUBMIT_URL).mock(
            return_value=httpx.Response(200, json={"uuid": "test-uuid-12345"})
        )
        # First two polls return 404 (still processing), third succeeds
        respx.get(URLSCAN_RESULT_URL.format(uuid="test-uuid-12345")).mock(
            side_effect=[
                httpx.Response(404),
                httpx.Response(404),
                httpx.Response(200, json=COMPLETE_RESULT),
            ]
        )

        result = tool.run("https://example.com")
        assert result.error is None
        assert result.data["uuid"] == "test-uuid-12345"

    @respx.mock
    def test_polling_timeout(self, tool, monkeypatch):
        """If polling never succeeds, should error gracefully with partial data."""
        # Cap polling attempts low so the test isn't doing 18 iterations
        monkeypatch.setattr("atlas.recon.urlscan.MAX_POLL_ATTEMPTS", 3)

        respx.post(URLSCAN_SUBMIT_URL).mock(
            return_value=httpx.Response(200, json={"uuid": "test-uuid-12345"})
        )
        # All polls return 404
        respx.get(URLSCAN_RESULT_URL.format(uuid="test-uuid-12345")).mock(
            return_value=httpx.Response(404)
        )

        result = tool.run("https://example.com")
        assert result.error is not None
        # Should still surface the UUID and report URL for manual checking
        assert result.data["uuid"] == "test-uuid-12345"
        assert "urlscan.io/result" in result.data["report_url"]

    # ── Data extraction ──────────────────────────────────────

    @respx.mock
    def test_screenshot_url_extracted(self, tool):
        """Screenshot URL should be in result data."""
        respx.post(URLSCAN_SUBMIT_URL).mock(
            return_value=httpx.Response(200, json={"uuid": "test-uuid-12345"})
        )
        respx.get(URLSCAN_RESULT_URL.format(uuid="test-uuid-12345")).mock(
            return_value=httpx.Response(200, json=COMPLETE_RESULT)
        )

        result = tool.run("https://example.com")
        assert "screenshot" in result.data["screenshot_url"]

    @respx.mock
    def test_contacted_domains_extracted(self, tool):
        """Contacted domains list should be populated."""
        respx.post(URLSCAN_SUBMIT_URL).mock(
            return_value=httpx.Response(200, json={"uuid": "test-uuid-12345"})
        )
        respx.get(URLSCAN_RESULT_URL.format(uuid="test-uuid-12345")).mock(
            return_value=httpx.Response(200, json=COMPLETE_RESULT)
        )

        result = tool.run("https://example.com")
        assert "example.com" in result.data["contacted_domains"]

    @respx.mock
    def test_page_geolocation_extracted(self, tool):
        """Where the page actually loaded from should be in the page section."""
        respx.post(URLSCAN_SUBMIT_URL).mock(
            return_value=httpx.Response(200, json={"uuid": "test-uuid-12345"})
        )
        respx.get(URLSCAN_RESULT_URL.format(uuid="test-uuid-12345")).mock(
            return_value=httpx.Response(200, json=COMPLETE_RESULT)
        )

        result = tool.run("https://example.com")
        page = result.data["page"]
        assert page["ip"] == "93.184.216.34"
        assert page["country"] == "US"
        assert page["umbrella_rank"] == 50
