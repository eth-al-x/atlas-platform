"""
Tests for the ATLAS FastAPI layer.

Uses FastAPI's TestClient (synchronous httpx wrapper) so we don't need
a running server. The pipeline and storage are mocked so tests are fast,
isolated, and don't touch the network or disk.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from atlas.api.main import create_app
from atlas.api import dependencies
from atlas.core.models import (
    ReconResult,
    ScanReport,
    ScanSource,
    ScanStats,
    TierResult,
    Verdict,
)


# ── Fixtures ──────────────────────────────────────────────────


def _make_report(verdict: Verdict = Verdict.CLEAN) -> ScanReport:
    """Build a minimal ScanReport for use in mocks."""
    return ScanReport(
        id=1,
        url="https://example.com",
        domain="example.com",
        final_verdict=verdict,
        tier_results=[
            TierResult(
                tier_name="local_blocklist",
                display_name="Local Blocklist",
                flagged=False,
                confidence=0.0,
            )
        ],
        scanned_at=datetime.now(timezone.utc),
        scan_duration_ms=42,
        source=ScanSource.API,
    )


def _make_recon_result(recon_type: str = "dns") -> ReconResult:
    return ReconResult(
        recon_type=recon_type,
        domain="example.com",
        data={"records": {"A": ["93.184.216.34"]}},
    )


@pytest.fixture
def mock_pipeline():
    """Mock AnalysisPipeline that returns a clean report."""
    pipeline = MagicMock()
    pipeline.tier_names = ["local_blocklist", "heuristics", "typosquat", "dnsbl", "virustotal"]
    pipeline.analyze.return_value = _make_report()
    return pipeline


@pytest.fixture
def mock_repo():
    """Mock ScanRepository."""
    repo = MagicMock()
    repo.save_scan.return_value = 1
    repo.get_scan.return_value = _make_report()
    repo.list_scans.return_value = [
        {
            "id": 1,
            "url": "https://example.com",
            "domain": "example.com",
            "final_verdict": "Clean",
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "scan_duration_ms": 42,
        }
    ]
    repo.get_stats.return_value = ScanStats(
        total_scans=10,
        high_risk=1,
        medium_risk=2,
        clean=7,
        scans_last_24h=3,
    )
    return repo


@pytest.fixture
def mock_tools():
    """Mock recon tool registry."""
    tools = {}
    for name in ["dns", "http_headers", "web_recon", "whois", "ip_intel",
                  "crtsh", "urlscan", "subdomains"]:
        tool = MagicMock()
        tool.run.return_value = _make_recon_result(name)
        tools[name] = tool
    return tools


@pytest.fixture
def client(mock_pipeline, mock_repo, mock_tools):
    """
    TestClient with all external dependencies mocked.
    Overrides FastAPI's dependency injection so tests are fully isolated.
    """
    app = create_app()

    # Override DI functions
    app.dependency_overrides[dependencies.get_pipeline] = lambda: mock_pipeline
    app.dependency_overrides[dependencies.get_repo] = lambda: mock_repo
    app.dependency_overrides[dependencies.get_atlas_config] = lambda: MagicMock()

    # Patch the tool cache used by get_tools
    import atlas.api.routes.recon as recon_module
    recon_module._tools = mock_tools

    with TestClient(app) as c:
        yield c

    # Clean up the module-level tool cache after each test
    recon_module._tools = None


# ── Health & Stats ────────────────────────────────────────────


class TestHealth:
    def test_health_check_returns_ok(self, client):
        response = client.get("/api/v1/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["version"] == "2.0.0"
        assert data["tiers_loaded"] == 5

    def test_root_redirects(self, client):
        """Root redirects to the dashboard if it's available, /docs otherwise."""
        response = client.get("/", follow_redirects=False)
        assert response.status_code in (301, 302, 307, 308)
        location = response.headers["location"]
        assert location in ("/dashboard", "/docs")


class TestStats:
    def test_stats_returns_aggregate(self, client):
        response = client.get("/api/v1/stats")
        assert response.status_code == 200
        data = response.json()
        assert data["stats"]["total_scans"] == 10
        assert data["stats"]["high_risk"] == 1
        assert data["stats"]["clean"] == 7
        assert "generated_at" in data

    def test_stats_accepts_days_param(self, client, mock_repo):
        response = client.get("/api/v1/stats?days=30")
        assert response.status_code == 200
        mock_repo.get_stats.assert_called_with(30)

    def test_stats_rejects_invalid_days(self, client):
        response = client.get("/api/v1/stats?days=0")
        assert response.status_code == 422  # Pydantic validation error


# ── Scan endpoints ────────────────────────────────────────────


class TestScanEndpoints:
    def test_post_scan_returns_report(self, client, mock_pipeline):
        response = client.post("/api/v1/scan", json={"url": "https://example.com"})
        assert response.status_code == 200
        data = response.json()
        assert data["scan"]["url"] == "https://example.com"
        assert data["scan"]["final_verdict"] == "Clean"
        assert "tier_results" in data["scan"]

    def test_post_scan_calls_pipeline(self, client, mock_pipeline):
        client.post("/api/v1/scan", json={"url": "https://example.com"})
        mock_pipeline.analyze.assert_called_once()
        call_args = mock_pipeline.analyze.call_args[0][0]
        assert call_args.url == "https://example.com"
        assert call_args.source.value == "api"

    def test_post_scan_persists_result(self, client, mock_repo):
        client.post("/api/v1/scan", json={"url": "https://example.com"})
        mock_repo.save_scan.assert_called_once()

    def test_post_scan_with_skip_tiers(self, client, mock_pipeline):
        client.post(
            "/api/v1/scan",
            json={"url": "https://example.com", "skip_tiers": ["virustotal"]},
        )
        call_args = mock_pipeline.analyze.call_args[0][0]
        assert "virustotal" in call_args.skip_tiers

    def test_get_scans_returns_list(self, client):
        response = client.get("/api/v1/scans")
        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert len(data["items"]) == 1
        assert data["items"][0]["domain"] == "example.com"

    def test_get_scans_pagination_params(self, client, mock_repo):
        client.get("/api/v1/scans?limit=5&offset=10")
        # Should fetch limit+1 to detect has_more
        mock_repo.list_scans.assert_called_with(6, 10)

    def test_get_scan_by_id_found(self, client):
        response = client.get("/api/v1/scans/1")
        assert response.status_code == 200
        data = response.json()
        assert data["scan"]["id"] == 1

    def test_get_scan_by_id_not_found(self, client, mock_repo):
        mock_repo.get_scan.return_value = None
        response = client.get("/api/v1/scans/999")
        assert response.status_code == 404
        assert "999" in response.json()["detail"]

    def test_high_risk_verdict_preserved(self, client, mock_pipeline):
        mock_pipeline.analyze.return_value = _make_report(Verdict.HIGH_RISK)
        response = client.post("/api/v1/scan", json={"url": "https://evil.com"})
        assert response.status_code == 200
        assert response.json()["scan"]["final_verdict"] == "High Risk"


# ── Recon endpoints ───────────────────────────────────────────


class TestReconEndpoints:
    def test_dns_lookup(self, client, mock_tools):
        response = client.get("/api/v1/recon/dns/example.com")
        assert response.status_code == 200
        data = response.json()
        assert data["result"]["recon_type"] == "dns"
        mock_tools["dns"].run.assert_called_with("example.com")

    def test_headers_lookup(self, client, mock_tools):
        response = client.get("/api/v1/recon/headers?url=https://example.com")
        assert response.status_code == 200
        mock_tools["http_headers"].run.assert_called_with("https://example.com")

    def test_headers_requires_url_param(self, client):
        response = client.get("/api/v1/recon/headers")
        assert response.status_code == 422

    def test_web_recon(self, client, mock_tools):
        response = client.get("/api/v1/recon/web?url=https://example.com")
        assert response.status_code == 200
        mock_tools["web_recon"].run.assert_called_with("https://example.com")

    def test_whois_lookup(self, client, mock_tools):
        response = client.get("/api/v1/recon/whois/example.com")
        assert response.status_code == 200
        mock_tools["whois"].run.assert_called_with("example.com")

    def test_ip_intel(self, client, mock_tools):
        response = client.get("/api/v1/recon/ip/example.com")
        assert response.status_code == 200
        mock_tools["ip_intel"].run.assert_called_with("example.com")

    def test_crtsh_lookup(self, client, mock_tools):
        response = client.get("/api/v1/recon/crtsh/example.com")
        assert response.status_code == 200
        mock_tools["crtsh"].run.assert_called_with("example.com")

    def test_urlscan(self, client, mock_tools):
        response = client.get("/api/v1/recon/urlscan?url=https://example.com")
        assert response.status_code == 200
        mock_tools["urlscan"].run.assert_called_with("https://example.com")

    def test_subdomains(self, client, mock_tools):
        response = client.get("/api/v1/recon/subdomains/example.com")
        assert response.status_code == 200
        mock_tools["subdomains"].run.assert_called_with("example.com")


# ── Investigate endpoint ──────────────────────────────────────


class TestInvestigateEndpoint:
    def test_investigate_returns_scan_and_recon(self, client):
        response = client.post(
            "/api/v1/investigate",
            json={"url": "https://example.com"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "scan" in data
        assert "recon" in data
        assert data["scan"]["url"] == "https://example.com"

    def test_investigate_runs_all_standard_tools(self, client, mock_tools):
        client.post("/api/v1/investigate", json={"url": "https://example.com"})
        # All non-slow tools should have been called
        for name in ["dns", "whois", "ip_intel", "crtsh", "http_headers", "web_recon"]:
            assert mock_tools[name].run.called, f"{name} was not called"

    def test_investigate_skip_slow_omits_urlscan(self, client, mock_tools):
        client.post(
            "/api/v1/investigate",
            json={"url": "https://example.com", "skip_slow": True},
        )
        mock_tools["urlscan"].run.assert_not_called()

    def test_investigate_with_subdomains_flag(self, client, mock_tools):
        client.post(
            "/api/v1/investigate",
            json={"url": "https://example.com", "include_subdomains": True},
        )
        mock_tools["subdomains"].run.assert_called()

    def test_investigate_without_subdomains_flag(self, client, mock_tools):
        client.post(
            "/api/v1/investigate",
            json={"url": "https://example.com", "include_subdomains": False},
        )
        mock_tools["subdomains"].run.assert_not_called()
