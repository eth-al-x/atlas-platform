"""
Tests for the dashboard-supporting API surface:
    - GET /api/v1/scans/{id}/recon
    - GET /api/v1/watches
    - POST /api/v1/watches
    - GET /api/v1/watches/{id}
    - DELETE /api/v1/watches/{id}
    - POST /api/v1/watches/run
    - GET /dashboard/ (static file mount)
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from atlas.api import dependencies
from atlas.api.main import create_app
from atlas.core.models import (
    ReconResult,
    ScanReport,
    ScanSource,
    ScanStats,
    TierResult,
    Verdict,
    WatchEntry,
)


# ── Helpers ───────────────────────────────────────────────────


def _make_report(scan_id: int = 1, verdict: Verdict = Verdict.MEDIUM_RISK) -> ScanReport:
    return ScanReport(
        id=scan_id,
        url="https://example.com",
        domain="example.com",
        final_verdict=verdict,
        tier_results=[
            TierResult(
                tier_name="heuristics",
                display_name="Heuristics",
                flagged=True,
                confidence=0.5,
            ),
        ],
        scanned_at=datetime.now(timezone.utc),
        scan_duration_ms=100,
        source=ScanSource.API,
    )


def _make_watch(watch_id: int = 1, domain: str = "example.com", **kwargs) -> WatchEntry:
    defaults = {
        "id": watch_id,
        "domain": domain,
        "url": f"https://{domain}",
        "active": True,
        "check_count": 0,
    }
    defaults.update(kwargs)
    return WatchEntry(**defaults)


# ── Fixtures ──────────────────────────────────────────────────


@pytest.fixture
def mock_pipeline():
    pipeline = MagicMock()
    pipeline.tier_names = ["heuristics"]
    pipeline.analyze.return_value = _make_report(verdict=Verdict.HIGH_RISK)
    return pipeline


@pytest.fixture
def mock_scan_repo():
    repo = MagicMock()
    repo.save_scan.return_value = 99
    repo.get_scan.return_value = _make_report(scan_id=1)
    repo.get_recon_results.return_value = {
        "dns": ReconResult(
            recon_type="dns",
            domain="example.com",
            data={"records": {"A": ["1.2.3.4"]}},
        ),
        "whois": ReconResult(
            recon_type="whois",
            domain="example.com",
            data={"registrar": "Acme Registrar"},
        ),
    }
    return repo


@pytest.fixture
def mock_watch_repo():
    repo = MagicMock()
    repo.add_watch.return_value = _make_watch(watch_id=1)
    repo.list_watches.return_value = [
        _make_watch(watch_id=1, domain="evil.com"),
        _make_watch(watch_id=2, domain="suspicious.io", last_verdict="High Risk"),
    ]
    repo.get_watch.return_value = _make_watch(watch_id=1)
    repo.remove_watch.return_value = True
    return repo


@pytest.fixture
def client(mock_pipeline, mock_scan_repo, mock_watch_repo):
    """TestClient with all dependencies mocked, including the new watch repo."""
    app = create_app()
    app.dependency_overrides[dependencies.get_pipeline] = lambda: mock_pipeline
    app.dependency_overrides[dependencies.get_repo] = lambda: mock_scan_repo
    app.dependency_overrides[dependencies.get_watch_repo] = lambda: mock_watch_repo
    app.dependency_overrides[dependencies.get_atlas_config] = lambda: MagicMock()
    with TestClient(app) as c:
        yield c


# ═══════════════════════════════════════════════════════════════
# GET /api/v1/scans/{id}/recon
# ═══════════════════════════════════════════════════════════════


class TestScanReconEndpoint:

    def test_returns_recon_data(self, client, mock_scan_repo):
        response = client.get("/api/v1/scans/1/recon")
        assert response.status_code == 200
        data = response.json()
        assert "dns" in data
        assert "whois" in data
        assert data["dns"]["data"]["records"]["A"] == ["1.2.3.4"]

    def test_404_when_scan_not_found(self, client, mock_scan_repo):
        mock_scan_repo.get_scan.return_value = None
        response = client.get("/api/v1/scans/99999/recon")
        assert response.status_code == 404

    def test_empty_recon_returns_empty_object(self, client, mock_scan_repo):
        mock_scan_repo.get_recon_results.return_value = {}
        response = client.get("/api/v1/scans/1/recon")
        assert response.status_code == 200
        assert response.json() == {}


# ═══════════════════════════════════════════════════════════════
# Watches API
# ═══════════════════════════════════════════════════════════════


class TestWatchListEndpoint:

    def test_list_all_watches(self, client, mock_watch_repo):
        response = client.get("/api/v1/watches")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 2
        assert data[0]["domain"] == "evil.com"

    def test_list_active_only(self, client, mock_watch_repo):
        client.get("/api/v1/watches?active=true")
        # active=True is what gets passed through to list_watches
        mock_watch_repo.list_watches.assert_called_with(True)


class TestAddWatchEndpoint:

    def test_add_domain(self, client, mock_watch_repo):
        response = client.post("/api/v1/watches", json={"target": "evil.com"})
        assert response.status_code == 201
        data = response.json()
        assert data["domain"] == "example.com"  # comes from mock return value
        mock_watch_repo.add_watch.assert_called_once()

    def test_add_url_extracts_domain(self, client, mock_watch_repo):
        client.post("/api/v1/watches", json={"target": "https://evil.com/path"})
        args, _ = mock_watch_repo.add_watch.call_args
        assert args[0] == "evil.com"          # domain
        assert args[1] == "https://evil.com/path"  # url

    def test_missing_target_rejected(self, client):
        response = client.post("/api/v1/watches", json={})
        assert response.status_code == 422


class TestGetWatchEndpoint:

    def test_returns_watch(self, client, mock_watch_repo):
        response = client.get("/api/v1/watches/1")
        assert response.status_code == 200
        assert response.json()["id"] == 1

    def test_404_when_not_found(self, client, mock_watch_repo):
        mock_watch_repo.get_watch.return_value = None
        response = client.get("/api/v1/watches/9999")
        assert response.status_code == 404


class TestRemoveWatchEndpoint:

    def test_removes_watch(self, client, mock_watch_repo):
        response = client.delete("/api/v1/watches/1")
        assert response.status_code == 200
        body = response.json()
        assert body["removed"] is True
        assert body["watch_id"] == 1

    def test_404_when_not_found(self, client, mock_watch_repo):
        mock_watch_repo.get_watch.return_value = None
        response = client.delete("/api/v1/watches/9999")
        assert response.status_code == 404


class TestRunWatchesEndpoint:

    def test_runs_all_active_watches(self, client, mock_watch_repo, mock_pipeline):
        response = client.post("/api/v1/watches/run", json={})
        assert response.status_code == 200
        alerts = response.json()
        # mock_watch_repo returns 2 active watches
        assert len(alerts) == 2
        # Pipeline should have been called once per watch
        assert mock_pipeline.analyze.call_count == 2

    def test_updates_each_watch(self, client, mock_watch_repo):
        client.post("/api/v1/watches/run", json={})
        # update_after_check called once per watch
        assert mock_watch_repo.update_after_check.call_count == 2

    def test_changed_only_filters_unchanged(self, client, mock_watch_repo, mock_pipeline):
        """When pipeline returns matching verdict for an existing watch, it should be filtered."""
        # Set up the second watch (suspicious.io) so its existing verdict
        # matches the new one (High Risk) — that one is unchanged.
        mock_watch_repo.list_watches.return_value = [
            _make_watch(watch_id=1, domain="evil.com"),                       # new
            _make_watch(watch_id=2, domain="suspicious.io", last_verdict="High Risk"),  # unchanged
        ]
        # Pipeline returns High Risk for both
        mock_pipeline.analyze.return_value = _make_report(verdict=Verdict.HIGH_RISK)

        response = client.post("/api/v1/watches/run", json={"changed_only": True})
        assert response.status_code == 200
        alerts = response.json()
        # The new one (is_new=True) should be kept; the unchanged one excluded.
        assert len(alerts) == 1
        assert alerts[0]["direction"] == "new"


# ═══════════════════════════════════════════════════════════════
# Dashboard static mount
# ═══════════════════════════════════════════════════════════════


class TestDashboardMount:

    def test_dashboard_index_served(self, client):
        response = client.get("/dashboard/")
        assert response.status_code == 200
        assert "ATLAS" in response.text
        assert "text/html" in response.headers["content-type"]

    def test_dashboard_css_served(self, client):
        response = client.get("/dashboard/style.css")
        assert response.status_code == 200
        assert "css" in response.headers["content-type"].lower()

    def test_dashboard_js_served(self, client):
        response = client.get("/dashboard/app.js")
        assert response.status_code == 200
        assert "javascript" in response.headers["content-type"].lower()

    def test_root_redirects_to_dashboard(self, client):
        response = client.get("/", follow_redirects=False)
        assert response.status_code in (301, 302, 307, 308)
        assert "/dashboard" in response.headers["location"]
