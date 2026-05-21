"""
Tests for the crt.sh Certificate Transparency recon tool.
Uses respx to mock httpx calls so tests don't hit the real crt.sh service.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import httpx
import pytest
import respx

from atlas.core.config import AtlasConfig
from atlas.recon.crtsh import CrtShReconTool, CRTSH_URL


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    """Don't actually sleep during retries in tests."""
    monkeypatch.setattr("time.sleep", lambda x: None)


@pytest.fixture
def tool():
    """Create a crt.sh recon tool."""
    return CrtShReconTool(AtlasConfig())


def _build_cert(name_value: str, issuer: str = "C=US, O=Let's Encrypt, CN=R3",
                entry_timestamp: str | None = None, days_ago: int = 365) -> dict:
    """Build a fake crt.sh cert entry."""
    if entry_timestamp is None:
        date = datetime.now(timezone.utc) - timedelta(days=days_ago)
        entry_timestamp = date.isoformat()
    return {
        "id": 12345,
        "name_value": name_value,
        "issuer_name": issuer,
        "entry_timestamp": entry_timestamp,
        "not_before": entry_timestamp,
        "not_after": (datetime.now(timezone.utc) + timedelta(days=90)).isoformat(),
    }


class TestCrtShReconTool:

    # ── Basic queries ────────────────────────────────────────

    @respx.mock
    def test_empty_response_handled(self, tool):
        """A domain with no certs in CT logs should return an empty summary."""
        respx.get(CRTSH_URL).mock(return_value=httpx.Response(200, json=[]))

        result = tool.run("example.com")

        assert result.error is None
        assert result.data["total_certs"] == 0
        assert result.data["subdomain_count"] == 0

    @respx.mock
    def test_single_cert_counted(self, tool):
        """A single cert should be reflected in total_certs."""
        respx.get(CRTSH_URL).mock(return_value=httpx.Response(200, json=[
            _build_cert("example.com")
        ]))

        result = tool.run("example.com")
        assert result.data["total_certs"] == 1

    # ── Subdomain extraction ─────────────────────────────────

    @respx.mock
    def test_unique_subdomains_extracted(self, tool):
        """Subdomains should be deduplicated and sorted."""
        respx.get(CRTSH_URL).mock(return_value=httpx.Response(200, json=[
            _build_cert("www.example.com\napi.example.com"),
            _build_cert("api.example.com"),  # duplicate
            _build_cert("dev.example.com\nstaging.example.com"),
        ]))

        result = tool.run("example.com")
        subs = result.data["unique_subdomains"]

        assert "www.example.com" in subs
        assert "api.example.com" in subs
        assert "dev.example.com" in subs
        assert "staging.example.com" in subs
        # Dedup check
        assert subs.count("api.example.com") == 1
        # Sorted check
        assert subs == sorted(subs)

    @respx.mock
    def test_unrelated_domains_filtered(self, tool):
        """Cert names not matching the target domain should be filtered out."""
        respx.get(CRTSH_URL).mock(return_value=httpx.Response(200, json=[
            _build_cert("api.example.com\napi.other.com"),
            _build_cert("unrelated.com"),
        ]))

        result = tool.run("example.com")
        subs = result.data["unique_subdomains"]

        assert "api.example.com" in subs
        assert "api.other.com" not in subs
        assert "unrelated.com" not in subs

    @respx.mock
    def test_wildcards_separated(self, tool):
        """Wildcard certs should be tracked separately from regular subdomains."""
        respx.get(CRTSH_URL).mock(return_value=httpx.Response(200, json=[
            _build_cert("*.example.com"),
            _build_cert("api.example.com"),
        ]))

        result = tool.run("example.com")

        assert "*.example.com" in result.data["wildcard_subdomains"]
        assert "api.example.com" in result.data["unique_subdomains"]
        assert "*.example.com" not in result.data["unique_subdomains"]

    @respx.mock
    def test_case_insensitive_name_matching(self, tool):
        """Cert names with uppercase should be normalized."""
        respx.get(CRTSH_URL).mock(return_value=httpx.Response(200, json=[
            _build_cert("API.EXAMPLE.COM\nWWW.EXAMPLE.COM"),
        ]))

        result = tool.run("example.com")
        subs = result.data["unique_subdomains"]

        assert "api.example.com" in subs
        assert "www.example.com" in subs

    # ── Issuer breakdown ─────────────────────────────────────

    @respx.mock
    def test_issuers_counted(self, tool):
        """Issuers should be counted and top 5 returned."""
        respx.get(CRTSH_URL).mock(return_value=httpx.Response(200, json=[
            _build_cert("a.example.com", issuer="C=US, O=Let's Encrypt, CN=R3"),
            _build_cert("b.example.com", issuer="C=US, O=Let's Encrypt, CN=R3"),
            _build_cert("c.example.com", issuer="C=US, O=DigiCert Inc, CN=DigiCert"),
        ]))

        result = tool.run("example.com")
        issuers = result.data["issuers"]

        assert issuers["Let's Encrypt"] == 2
        assert issuers["DigiCert Inc"] == 1

    # ── Recent certs detection ──────────────────────────────

    @respx.mock
    def test_recent_certs_counted(self, tool):
        """Certs issued within last 30 days should be flagged."""
        respx.get(CRTSH_URL).mock(return_value=httpx.Response(200, json=[
            _build_cert("a.example.com", days_ago=5),   # recent
            _build_cert("b.example.com", days_ago=10),  # recent
            _build_cert("c.example.com", days_ago=100), # not recent
        ]))

        result = tool.run("example.com")
        assert result.data["recent_certs_30d"] == 2

    # ── Date range ──────────────────────────────────────────

    @respx.mock
    def test_oldest_and_newest_cert_dates(self, tool):
        """Date range across certs should be tracked."""
        respx.get(CRTSH_URL).mock(return_value=httpx.Response(200, json=[
            _build_cert("a.example.com", days_ago=500),  # oldest
            _build_cert("b.example.com", days_ago=100),
            _build_cert("c.example.com", days_ago=10),   # newest
        ]))

        result = tool.run("example.com")

        assert result.data["oldest_cert_date"] is not None
        assert result.data["newest_cert_date"] is not None
        assert result.data["oldest_cert_date"] < result.data["newest_cert_date"]

    # ── Error handling ──────────────────────────────────────

    @respx.mock
    def test_http_error_captured(self, tool):
        """An HTTP error should produce a clean error result."""
        respx.get(CRTSH_URL).mock(return_value=httpx.Response(502))

        result = tool.run("example.com")
        assert result.error is not None

    @respx.mock
    def test_timeout_captured(self, tool):
        """A timeout should produce a clean error result."""
        respx.get(CRTSH_URL).mock(side_effect=httpx.TimeoutException("timed out"))

        result = tool.run("example.com")
        assert result.error is not None

    @respx.mock
    def test_invalid_json_handled(self, tool):
        """Malformed JSON from crt.sh should not crash the tool."""
        respx.get(CRTSH_URL).mock(
            return_value=httpx.Response(200, text="this is not json")
        )

        result = tool.run("example.com")
        assert result.error is not None
