"""
Tests for the IP intelligence recon tool.
Mocks socket.gethostbyname and the httpx calls to ip-api and Shodan.
"""

from __future__ import annotations

import socket
from unittest.mock import patch

import httpx
import pytest
import respx

from atlas.core.config import AtlasConfig
from atlas.recon.ip_intel import IPIntelReconTool


@pytest.fixture
def tool():
    """Create an IP intel recon tool."""
    return IPIntelReconTool(AtlasConfig())


# Reusable mock responses
GEO_SUCCESS = {
    "status": "success",
    "country": "United States",
    "regionName": "California",
    "city": "San Francisco",
    "zip": "94102",
    "lat": 37.7749,
    "lon": -122.4194,
    "timezone": "America/Los_Angeles",
    "isp": "Example ISP",
    "org": "Example Hosting",
    "as": "AS12345 Example Network",
    "query": "1.2.3.4",
}

SHODAN_SUCCESS = {
    "ip": "1.2.3.4",
    "ports": [80, 443, 22],
    "hostnames": ["example.com", "www.example.com"],
    "cpes": ["cpe:/a:nginx:nginx:1.18.0"],
    "tags": ["cloud"],
    "vulns": [],
}


class TestIPIntelReconTool:

    # ── Resolution failures ──────────────────────────────────

    def test_unresolvable_domain_returns_error(self, tool):
        """A domain that can't be resolved should produce a clean error."""
        with patch("atlas.recon.ip_intel.socket.gethostbyname",
                   side_effect=socket.gaierror("name resolution failed")):
            result = tool.run("nonexistent-xyz.invalid")

        assert result.error is not None
        assert "could not resolve" in result.error.lower()

    # ── Successful flow ──────────────────────────────────────

    @respx.mock
    def test_returns_ip_address(self, tool):
        """Resolved IP should appear in result data."""
        respx.get("http://ip-api.com/json/1.2.3.4").mock(
            return_value=httpx.Response(200, json=GEO_SUCCESS)
        )
        respx.get("https://internetdb.shodan.io/1.2.3.4").mock(
            return_value=httpx.Response(200, json=SHODAN_SUCCESS)
        )

        with patch("atlas.recon.ip_intel.socket.gethostbyname", return_value="1.2.3.4"):
            result = tool.run("example.com")

        assert result.data["ip"] == "1.2.3.4"

    @respx.mock
    def test_geolocation_data_extracted(self, tool):
        """Geolocation fields should be extracted from ip-api response."""
        respx.get("http://ip-api.com/json/1.2.3.4").mock(
            return_value=httpx.Response(200, json=GEO_SUCCESS)
        )
        respx.get("https://internetdb.shodan.io/1.2.3.4").mock(
            return_value=httpx.Response(404)
        )

        with patch("atlas.recon.ip_intel.socket.gethostbyname", return_value="1.2.3.4"):
            result = tool.run("example.com")

        geo = result.data["geolocation"]
        assert geo["country"] == "United States"
        assert geo["city"] == "San Francisco"
        assert geo["isp"] == "Example ISP"
        assert "AS12345" in geo["asn"]

    @respx.mock
    def test_shodan_data_extracted(self, tool):
        """Shodan InternetDB fields should be extracted."""
        respx.get("http://ip-api.com/json/1.2.3.4").mock(
            return_value=httpx.Response(200, json=GEO_SUCCESS)
        )
        respx.get("https://internetdb.shodan.io/1.2.3.4").mock(
            return_value=httpx.Response(200, json=SHODAN_SUCCESS)
        )

        with patch("atlas.recon.ip_intel.socket.gethostbyname", return_value="1.2.3.4"):
            result = tool.run("example.com")

        exposure = result.data["exposure"]
        assert exposure["open_ports"] == [22, 80, 443]  # sorted
        assert "example.com" in exposure["hostnames"]
        assert exposure["tags"] == ["cloud"]

    # ── Partial-failure handling ─────────────────────────────

    @respx.mock
    def test_ip_api_failure_does_not_kill_lookup(self, tool):
        """If ip-api fails, Shodan data should still come through."""
        respx.get("http://ip-api.com/json/1.2.3.4").mock(
            side_effect=httpx.TimeoutException("timed out")
        )
        respx.get("https://internetdb.shodan.io/1.2.3.4").mock(
            return_value=httpx.Response(200, json=SHODAN_SUCCESS)
        )

        with patch("atlas.recon.ip_intel.socket.gethostbyname", return_value="1.2.3.4"):
            result = tool.run("example.com")

        # Geo has an error but Shodan succeeded
        assert "error" in result.data["geolocation"]
        assert result.data["exposure"]["open_ports"] == [22, 80, 443]

    @respx.mock
    def test_shodan_404_means_no_data(self, tool):
        """Shodan 404 is normal (no exposure data) — should not be an error."""
        respx.get("http://ip-api.com/json/1.2.3.4").mock(
            return_value=httpx.Response(200, json=GEO_SUCCESS)
        )
        respx.get("https://internetdb.shodan.io/1.2.3.4").mock(
            return_value=httpx.Response(404)
        )

        with patch("atlas.recon.ip_intel.socket.gethostbyname", return_value="1.2.3.4"):
            result = tool.run("example.com")

        assert "note" in result.data["exposure"]
        assert "error" not in result.data["exposure"]

    @respx.mock
    def test_ip_api_fail_status_captured(self, tool):
        """ip-api returns status=fail for some queries; capture as error."""
        respx.get("http://ip-api.com/json/1.2.3.4").mock(
            return_value=httpx.Response(200, json={
                "status": "fail",
                "message": "private range",
            })
        )
        respx.get("https://internetdb.shodan.io/1.2.3.4").mock(
            return_value=httpx.Response(404)
        )

        with patch("atlas.recon.ip_intel.socket.gethostbyname", return_value="1.2.3.4"):
            result = tool.run("example.com")

        assert result.data["geolocation"]["error"] == "private range"
