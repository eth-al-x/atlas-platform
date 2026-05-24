"""
Tests for the GreyNoise recon tool.
Mocks socket.gethostbyname and all httpx calls to the GreyNoise API.
"""

from __future__ import annotations

import socket
from unittest.mock import patch

import httpx
import pytest
import respx

from atlas.core.config import AtlasConfig
from atlas.recon.greynoise import GreyNoiseReconTool


@pytest.fixture
def tool(monkeypatch):
    """Tool with no API key — explicitly unset to override any value in .env."""
    monkeypatch.delenv("GREYNOISE_API_KEY", raising=False)
    return GreyNoiseReconTool(AtlasConfig())


@pytest.fixture
def tool_with_key(monkeypatch):
    monkeypatch.setenv("GREYNOISE_API_KEY", "test-key-abc123")
    return GreyNoiseReconTool(AtlasConfig())


# ── Reusable mock payloads ────────────────────────────────────

GN_MALICIOUS = {
    "ip": "1.2.3.4",
    "noise": True,
    "riot": False,
    "classification": "malicious",
    "name": "ThreatActor-42",
    "link": "https://viz.greynoise.io/ip/1.2.3.4",
    "last_seen": "2024-11-01",
    "message": "Success",
}

GN_BENIGN_RIOT = {
    "ip": "8.8.8.8",
    "noise": False,
    "riot": True,
    "classification": "benign",
    "name": "Google Public DNS",
    "link": "https://viz.greynoise.io/ip/8.8.8.8",
    "last_seen": "2024-11-10",
    "message": "This IP is commonly included in blocklists, but is owned by a legitimate company.",
}

GN_NOISE_UNKNOWN = {
    "ip": "5.6.7.8",
    "noise": True,
    "riot": False,
    "classification": "unknown",
    "name": None,
    "link": "https://viz.greynoise.io/ip/5.6.7.8",
    "last_seen": "2024-10-30",
    "message": "Success",
}


class TestGreyNoiseResolution:

    def test_unresolvable_domain_returns_error(self, tool):
        """A domain that can't be resolved should produce a clean error."""
        with patch("atlas.recon.greynoise.socket.gethostbyname",
                   side_effect=socket.gaierror("name resolution failed")):
            result = tool.run("nonexistent-xyz.invalid")

        assert result.error is not None
        assert "could not resolve" in result.error.lower()

    @respx.mock
    def test_resolved_ip_included_in_data(self, tool):
        """The resolved IP should appear in result data."""
        respx.get("https://api.greynoise.io/v3/community/1.2.3.4").mock(
            return_value=httpx.Response(200, json=GN_MALICIOUS)
        )
        with patch("atlas.recon.greynoise.socket.gethostbyname", return_value="1.2.3.4"):
            result = tool.run("evil.example.com")

        assert result.data["ip"] == "1.2.3.4"
        assert result.error is None


class TestGreyNoiseClassifications:

    @respx.mock
    def test_malicious_classification(self, tool):
        """Malicious IP should be classified correctly with all fields."""
        respx.get("https://api.greynoise.io/v3/community/1.2.3.4").mock(
            return_value=httpx.Response(200, json=GN_MALICIOUS)
        )
        with patch("atlas.recon.greynoise.socket.gethostbyname", return_value="1.2.3.4"):
            result = tool.run("evil.example.com")

        assert result.data["classification"] == "malicious"
        assert result.data["noise"] is True
        assert result.data["riot"] is False
        assert result.data["seen"] is True
        assert result.data["name"] == "ThreatActor-42"
        assert result.data["last_seen"] == "2024-11-01"

    @respx.mock
    def test_riot_benign_classification(self, tool):
        """Known-benign RIOT IPs should be marked riot=True."""
        respx.get("https://api.greynoise.io/v3/community/8.8.8.8").mock(
            return_value=httpx.Response(200, json=GN_BENIGN_RIOT)
        )
        with patch("atlas.recon.greynoise.socket.gethostbyname", return_value="8.8.8.8"):
            result = tool.run("google-dns.example.com")

        assert result.data["riot"] is True
        assert result.data["classification"] == "benign"
        assert result.data["name"] == "Google Public DNS"
        assert result.error is None

    @respx.mock
    def test_noisy_unknown_classification(self, tool):
        """An IP that scans but has no known actor should be noise=True, classification=unknown."""
        respx.get("https://api.greynoise.io/v3/community/5.6.7.8").mock(
            return_value=httpx.Response(200, json=GN_NOISE_UNKNOWN)
        )
        with patch("atlas.recon.greynoise.socket.gethostbyname", return_value="5.6.7.8"):
            result = tool.run("example.com")

        assert result.data["noise"] is True
        assert result.data["classification"] == "unknown"
        assert result.data["name"] is None


class TestGreyNoiseNotSeen:

    @respx.mock
    def test_404_returns_not_seen_result(self, tool):
        """404 means IP is not in GreyNoise dataset — not an error, just not_seen."""
        respx.get("https://api.greynoise.io/v3/community/9.9.9.9").mock(
            return_value=httpx.Response(404)
        )
        with patch("atlas.recon.greynoise.socket.gethostbyname", return_value="9.9.9.9"):
            result = tool.run("quiet.example.com")

        assert result.error is None
        assert result.data["seen"] is False
        assert result.data["classification"] == "not_seen"
        assert result.data["noise"] is False
        assert result.data["riot"] is False


class TestGreyNoiseAuthAndRateLimits:

    @respx.mock
    def test_401_returns_error_message(self, tool):
        """401 from GreyNoise should produce a descriptive error, not an exception."""
        respx.get("https://api.greynoise.io/v3/community/1.2.3.4").mock(
            return_value=httpx.Response(401)
        )
        with patch("atlas.recon.greynoise.socket.gethostbyname", return_value="1.2.3.4"):
            result = tool.run("example.com")

        assert result.error is None  # graceful — error is in data, not result.error
        assert "error" in result.data
        assert "key" in result.data["error"].lower()

    @respx.mock
    def test_429_rate_limit_returns_error_message(self, tool):
        """429 from GreyNoise should produce a rate-limit error message."""
        respx.get("https://api.greynoise.io/v3/community/1.2.3.4").mock(
            return_value=httpx.Response(429)
        )
        with patch("atlas.recon.greynoise.socket.gethostbyname", return_value="1.2.3.4"):
            result = tool.run("example.com")

        assert result.error is None
        assert "error" in result.data
        assert "rate limit" in result.data["error"].lower()

    @respx.mock
    def test_api_key_is_sent_in_header(self, tool_with_key):
        """When GREYNOISE_API_KEY is set, it should be sent in the 'key' header."""
        request_headers: dict = {}

        def capture(request: httpx.Request) -> httpx.Response:
            request_headers.update(dict(request.headers))
            return httpx.Response(200, json=GN_MALICIOUS)

        respx.get("https://api.greynoise.io/v3/community/1.2.3.4").mock(side_effect=capture)
        with patch("atlas.recon.greynoise.socket.gethostbyname", return_value="1.2.3.4"):
            tool_with_key.run("example.com")

        assert request_headers.get("key") == "test-key-abc123"

    @respx.mock
    def test_no_key_sends_no_auth_header(self, tool):
        """Without a key configured, no 'key' header should be sent."""
        request_headers: dict = {}

        def capture(request: httpx.Request) -> httpx.Response:
            request_headers.update(dict(request.headers))
            return httpx.Response(200, json=GN_MALICIOUS)

        respx.get("https://api.greynoise.io/v3/community/1.2.3.4").mock(side_effect=capture)
        with patch("atlas.recon.greynoise.socket.gethostbyname", return_value="1.2.3.4"):
            tool.run("example.com")

        assert "key" not in request_headers


class TestGreyNoiseNetworkErrors:

    @respx.mock
    def test_network_timeout_produces_error_in_data(self, tool):
        """A network timeout should be captured in data['error'], not raise."""
        respx.get("https://api.greynoise.io/v3/community/1.2.3.4").mock(
            side_effect=httpx.TimeoutException("timed out")
        )
        with patch("atlas.recon.greynoise.socket.gethostbyname", return_value="1.2.3.4"):
            result = tool.run("example.com")

        # Base class catches unexpected exceptions in run(); network errors in
        # _query_greynoise() land in data["error"]
        assert result.data.get("error") is not None or result.error is not None

    @respx.mock
    def test_connection_error_produces_error(self, tool):
        """A connection error should be captured gracefully."""
        respx.get("https://api.greynoise.io/v3/community/1.2.3.4").mock(
            side_effect=httpx.ConnectError("connection refused")
        )
        with patch("atlas.recon.greynoise.socket.gethostbyname", return_value="1.2.3.4"):
            result = tool.run("example.com")

        assert result.data.get("error") is not None or result.error is not None


class TestGreyNoiseResultShape:

    @respx.mock
    def test_recon_type_is_set(self, tool):
        """result.recon_type should be 'greynoise'."""
        respx.get("https://api.greynoise.io/v3/community/1.2.3.4").mock(
            return_value=httpx.Response(200, json=GN_MALICIOUS)
        )
        with patch("atlas.recon.greynoise.socket.gethostbyname", return_value="1.2.3.4"):
            result = tool.run("example.com")

        assert result.recon_type == "greynoise"

    @respx.mock
    def test_domain_is_preserved(self, tool):
        """result.domain should be the original target, not the resolved IP."""
        respx.get("https://api.greynoise.io/v3/community/1.2.3.4").mock(
            return_value=httpx.Response(200, json=GN_MALICIOUS)
        )
        with patch("atlas.recon.greynoise.socket.gethostbyname", return_value="1.2.3.4"):
            result = tool.run("evil.example.com")

        assert result.domain == "evil.example.com"

    @respx.mock
    def test_duration_is_recorded(self, tool):
        """_duration_ms should be set in data by the base class."""
        respx.get("https://api.greynoise.io/v3/community/1.2.3.4").mock(
            return_value=httpx.Response(200, json=GN_MALICIOUS)
        )
        with patch("atlas.recon.greynoise.socket.gethostbyname", return_value="1.2.3.4"):
            result = tool.run("example.com")

        assert "_duration_ms" in result.data
        assert isinstance(result.data["_duration_ms"], int)
