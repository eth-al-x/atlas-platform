"""
Tests for the Censys Certificates recon tool.
Mocks all httpx POST calls to the Censys search API.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from atlas.core.config import AtlasConfig
from atlas.recon.censys_certs import CensysCertsReconTool, CENSYS_SEARCH_URL


# ── Fixtures ──────────────────────────────────────────────────

@pytest.fixture
def tool(monkeypatch):
    """Tool with credentials set."""
    monkeypatch.setenv("CENSYS_API_ID", "test-id")
    monkeypatch.setenv("CENSYS_API_SECRET", "test-secret")
    return CensysCertsReconTool(AtlasConfig())


@pytest.fixture
def tool_no_creds(monkeypatch):
    """Tool with no credentials — simulates unconfigured state."""
    monkeypatch.delenv("CENSYS_API_ID", raising=False)
    monkeypatch.delenv("CENSYS_API_SECRET", raising=False)
    return CensysCertsReconTool(AtlasConfig())


# ── Response builders ─────────────────────────────────────────

def _cert_hit(
    names: list[str],
    issuer_org: str = "Let's Encrypt",
    validation_type: str = "DV",
    not_before: str = "2024-01-01T00:00:00Z",
    not_after: str = "2024-04-01T00:00:00Z",
    fingerprint: str = "abc123",
    self_signed: bool = False,
    key_algorithm: str = "RSA",
) -> dict:
    subject_dn = f"CN={names[0]}" if names else "CN=example.com"
    issuer_dn = subject_dn if self_signed else f"CN=R3, O={issuer_org}, C=US"
    return {
        "fingerprint_sha256": fingerprint,
        "names": names,
        "parsed": {
            "subject_dn": subject_dn,
            "issuer_dn": issuer_dn,
            "issuer": {"organization": [issuer_org]},
            "validity": {"start": not_before, "end": not_after},
            "names": names,
            "subject_key_info": {"key_algorithm": {"name": key_algorithm}},
        },
        "validation": {
            "nss": {"valid": True, "type": validation_type},
        },
    }


def _page_response(
    hits: list[dict],
    total: int = 0,
    next_cursor: str | None = None,
) -> dict:
    return {
        "code": 200,
        "status": "OK",
        "result": {
            "query": "names: example.com",
            "total": total or len(hits),
            "hits": hits,
            "links": {
                "next": next_cursor,
                "prev": None,
            },
        },
    }


# ── No credentials ────────────────────────────────────────────

class TestCensysNoCredentials:

    def test_missing_credentials_returns_skip_result(self, tool_no_creds):
        """Without API credentials, tool should return a no-credentials result, not error."""
        result = tool_no_creds.run("example.com")

        assert result.error is None
        assert result.data["no_credentials"] is True
        assert "note" in result.data
        assert result.data["total_certs"] == 0

    def test_missing_credentials_makes_no_http_calls(self, tool_no_creds):
        """Without credentials, no HTTP requests should be made."""
        with respx.mock(assert_all_called=False) as mock:
            result = tool_no_creds.run("example.com")
        # If any HTTP call had been made to respx without a matching route,
        # it would have raised. The no-credentials path should never get here.
        assert result.data["no_credentials"] is True


# ── Successful queries ────────────────────────────────────────

class TestCensysSuccessfulQuery:

    @respx.mock
    def test_single_page_result(self, tool):
        """Single page of results should populate certs and unique_sans."""
        hits = [
            _cert_hit(["example.com", "www.example.com"], fingerprint="fp1"),
            _cert_hit(["api.example.com"], fingerprint="fp2"),
        ]
        respx.post(CENSYS_SEARCH_URL).mock(
            return_value=httpx.Response(200, json=_page_response(hits, total=2))
        )

        result = tool.run("example.com")

        assert result.error is None
        assert result.data["total_certs"] == 2
        assert "www.example.com" in result.data["unique_sans"]
        assert "api.example.com" in result.data["unique_sans"]

    @respx.mock
    def test_unique_sans_are_deduplicated(self, tool):
        """The same SAN appearing in multiple certs should only appear once."""
        hits = [
            _cert_hit(["example.com", "www.example.com"], fingerprint="fp1"),
            _cert_hit(["example.com", "www.example.com"], fingerprint="fp2"),
        ]
        respx.post(CENSYS_SEARCH_URL).mock(
            return_value=httpx.Response(200, json=_page_response(hits))
        )

        result = tool.run("example.com")

        assert result.data["unique_sans"].count("www.example.com") == 1
        assert result.data["unique_sans"].count("example.com") == 1

    @respx.mock
    def test_unique_sans_are_sorted(self, tool):
        """unique_sans should be returned in sorted order."""
        hits = [
            _cert_hit(["www.example.com", "api.example.com", "dev.example.com"]),
        ]
        respx.post(CENSYS_SEARCH_URL).mock(
            return_value=httpx.Response(200, json=_page_response(hits))
        )

        result = tool.run("example.com")
        sans = result.data["unique_sans"]
        assert sans == sorted(sans)

    @respx.mock
    def test_issuer_counts_populated(self, tool):
        """Issuer organizations should be counted."""
        hits = [
            _cert_hit(["example.com"], issuer_org="Let's Encrypt", fingerprint="fp1"),
            _cert_hit(["www.example.com"], issuer_org="Let's Encrypt", fingerprint="fp2"),
            _cert_hit(["api.example.com"], issuer_org="DigiCert", fingerprint="fp3"),
        ]
        respx.post(CENSYS_SEARCH_URL).mock(
            return_value=httpx.Response(200, json=_page_response(hits))
        )

        result = tool.run("example.com")

        counts = result.data["issuer_counts"]
        assert counts["Let's Encrypt"] == 2
        assert counts["DigiCert"] == 1

    @respx.mock
    def test_unique_issuers_list(self, tool):
        """unique_issuers should list all distinct issuer orgs."""
        hits = [
            _cert_hit(["example.com"], issuer_org="Let's Encrypt", fingerprint="fp1"),
            _cert_hit(["www.example.com"], issuer_org="DigiCert", fingerprint="fp2"),
        ]
        respx.post(CENSYS_SEARCH_URL).mock(
            return_value=httpx.Response(200, json=_page_response(hits))
        )

        result = tool.run("example.com")

        assert "Let's Encrypt" in result.data["unique_issuers"]
        assert "DigiCert" in result.data["unique_issuers"]

    @respx.mock
    def test_recon_type_and_domain_set(self, tool):
        """result.recon_type and result.domain should be set correctly."""
        respx.post(CENSYS_SEARCH_URL).mock(
            return_value=httpx.Response(200, json=_page_response([]))
        )

        result = tool.run("example.com")

        assert result.recon_type == "censys_certs"
        assert result.domain == "example.com"

    @respx.mock
    def test_duration_recorded(self, tool):
        """_duration_ms should be populated by the base class."""
        respx.post(CENSYS_SEARCH_URL).mock(
            return_value=httpx.Response(200, json=_page_response([]))
        )

        result = tool.run("example.com")
        assert "_duration_ms" in result.data
        assert isinstance(result.data["_duration_ms"], int)


# ── Validation levels ─────────────────────────────────────────

class TestCensysValidationLevels:

    @respx.mock
    def test_dv_only_flag(self, tool):
        """All-DV cert history should set dv_only=True."""
        hits = [
            _cert_hit(["example.com"], validation_type="DV", fingerprint="fp1"),
            _cert_hit(["www.example.com"], validation_type="DV", fingerprint="fp2"),
        ]
        respx.post(CENSYS_SEARCH_URL).mock(
            return_value=httpx.Response(200, json=_page_response(hits))
        )

        result = tool.run("example.com")
        assert result.data["dv_only"] is True
        assert result.data["has_ov_ev"] is False

    @respx.mock
    def test_has_ov_ev_flag(self, tool):
        """Mixed DV + OV certs should set has_ov_ev=True, dv_only=False."""
        hits = [
            _cert_hit(["example.com"], validation_type="DV", fingerprint="fp1"),
            _cert_hit(["www.example.com"], validation_type="OV", fingerprint="fp2"),
        ]
        respx.post(CENSYS_SEARCH_URL).mock(
            return_value=httpx.Response(200, json=_page_response(hits))
        )

        result = tool.run("example.com")
        assert result.data["has_ov_ev"] is True
        assert result.data["dv_only"] is False

    @respx.mock
    def test_ev_cert_sets_has_ov_ev(self, tool):
        """EV cert should also set has_ov_ev=True."""
        hits = [
            _cert_hit(["example.com"], validation_type="EV", fingerprint="fp1"),
        ]
        respx.post(CENSYS_SEARCH_URL).mock(
            return_value=httpx.Response(200, json=_page_response(hits))
        )

        result = tool.run("example.com")
        assert result.data["has_ov_ev"] is True

    @respx.mock
    def test_validation_breakdown_populated(self, tool):
        """validation_breakdown should count each validation level."""
        hits = [
            _cert_hit(["example.com"], validation_type="DV", fingerprint="fp1"),
            _cert_hit(["example.com"], validation_type="DV", fingerprint="fp2"),
            _cert_hit(["example.com"], validation_type="OV", fingerprint="fp3"),
        ]
        respx.post(CENSYS_SEARCH_URL).mock(
            return_value=httpx.Response(200, json=_page_response(hits))
        )

        result = tool.run("example.com")
        breakdown = result.data["validation_breakdown"]
        assert breakdown["DV"] == 2
        assert breakdown["OV"] == 1

    @respx.mock
    def test_self_signed_detection(self, tool):
        """Certs where subject_dn == issuer_dn should be marked self_signed=True."""
        hits = [_cert_hit(["example.com"], self_signed=True, fingerprint="fp1")]
        respx.post(CENSYS_SEARCH_URL).mock(
            return_value=httpx.Response(200, json=_page_response(hits))
        )

        result = tool.run("example.com")
        assert result.data["certs"][0]["self_signed"] is True


# ── Pagination ────────────────────────────────────────────────

class TestCensysPagination:

    @respx.mock
    def test_follows_cursor_to_second_page(self, tool):
        """When next_cursor is set, a second request should be made with it."""
        page1_hits = [_cert_hit(["www.example.com"], fingerprint="fp1")]
        page2_hits = [_cert_hit(["api.example.com"], fingerprint="fp2")]

        call_count = 0

        def respond(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            body = __import__("json").loads(request.content)
            if body.get("cursor") == "cursor-abc":
                return httpx.Response(200, json=_page_response(page2_hits, next_cursor=None))
            return httpx.Response(200, json=_page_response(page1_hits, next_cursor="cursor-abc"))

        respx.post(CENSYS_SEARCH_URL).mock(side_effect=respond)

        result = tool.run("example.com")

        assert call_count == 2
        assert result.data["total_certs"] == 2
        sans = result.data["unique_sans"]
        assert "www.example.com" in sans
        assert "api.example.com" in sans

    @respx.mock
    def test_stops_when_no_next_cursor(self, tool):
        """Pagination should stop when next_cursor is None or absent."""
        hits = [_cert_hit(["example.com"], fingerprint="fp1")]
        call_count = 0

        def respond(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            return httpx.Response(200, json=_page_response(hits, next_cursor=None))

        respx.post(CENSYS_SEARCH_URL).mock(side_effect=respond)
        tool.run("example.com")

        assert call_count == 1

    @respx.mock
    def test_truncated_flag_when_max_pages_reached(self, tool):
        """truncated=True when we hit max_pages and more data exists."""
        # Set a low max_pages to make testing fast
        tool.max_pages = 2
        tool.per_page = 1

        hits_per_page = [_cert_hit([f"sub{i}.example.com"], fingerprint=f"fp{i}") for i in range(1)]

        call_count = 0

        def respond(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            # Always return a next cursor — simulates infinite results
            return httpx.Response(
                200,
                json=_page_response(hits_per_page, total=999, next_cursor="next"),
            )

        respx.post(CENSYS_SEARCH_URL).mock(side_effect=respond)
        result = tool.run("example.com")

        assert result.data["truncated"] is True
        assert call_count == 2


# ── Auth and error codes ──────────────────────────────────────

class TestCensysAuthAndErrors:

    @respx.mock
    def test_401_captured_gracefully(self, tool):
        """401 should not raise; tool should return an error result."""
        respx.post(CENSYS_SEARCH_URL).mock(return_value=httpx.Response(401))
        result = tool.run("example.com")
        # 401 stops pagination and returns empty — handled in _fetch_page
        assert result.error is None
        assert result.data["total_certs"] == 0

    @respx.mock
    def test_429_rate_limit_captured(self, tool):
        """429 should stop pagination gracefully."""
        respx.post(CENSYS_SEARCH_URL).mock(return_value=httpx.Response(429))
        result = tool.run("example.com")
        assert result.error is None
        assert result.data["total_certs"] == 0

    @respx.mock
    def test_network_timeout_captured(self, tool):
        """Network timeout should not propagate as an unhandled exception."""
        respx.post(CENSYS_SEARCH_URL).mock(
            side_effect=httpx.TimeoutException("timed out")
        )
        result = tool.run("example.com")
        # Base class catches anything _run() raises; _fetch_page handles http errors
        assert result.data["total_certs"] == 0 or result.error is not None

    @respx.mock
    def test_credentials_sent_as_basic_auth(self, tool):
        """API ID and secret should be sent as HTTP Basic Auth."""
        import base64

        captured_headers: dict = {}

        def capture(request: httpx.Request) -> httpx.Response:
            captured_headers.update(dict(request.headers))
            return httpx.Response(200, json=_page_response([]))

        respx.post(CENSYS_SEARCH_URL).mock(side_effect=capture)
        tool.run("example.com")

        auth_header = captured_headers.get("authorization", "")
        assert auth_header.startswith("Basic ")
        decoded = base64.b64decode(auth_header[6:]).decode()
        assert decoded == "test-id:test-secret"

    @respx.mock
    def test_empty_result_set(self, tool):
        """A domain with zero certs should return a clean empty result."""
        respx.post(CENSYS_SEARCH_URL).mock(
            return_value=httpx.Response(200, json=_page_response([], total=0))
        )

        result = tool.run("example.com")

        assert result.error is None
        assert result.data["total_certs"] == 0
        assert result.data["unique_sans"] == []
        assert result.data["dv_only"] is False
