"""
Tests for favicon hashing and the favicon pivot chain.

Coverage:
    1. Shodan-compatible MMH3 recipe (base64-encode → mmh3)
    2. Favicon URL discovery (link tag preference, fallback, data: rejection)
    3. End-to-end _collect_favicon with mocked HTTP client
    4. ScanRepository.find_related_scans favicon_hash queries
    5. CrossScanCorrelator favicon pivot extraction
    6. CLI: atlas pivot favicon
    7. API: GET /api/v1/pivot/favicon/{hash}
"""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from unittest.mock import MagicMock

import mmh3
import pytest
from bs4 import BeautifulSoup
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from atlas.api import dependencies
from atlas.api.main import create_app
from atlas.cli.main import app
from atlas.core.config import get_config
from atlas.core.models import (
    CorrelationContext,
    ReconResult,
    ScanReport,
    ScanSource,
    TierResult,
    Verdict,
)
from atlas.correlate.cross_scan import CrossScanCorrelator
from atlas.recon.web_recon import WebReconTool
from atlas.storage.db import ScanRepository


# ═══════════════════════════════════════════════════════════════
# 1. Hash recipe
# ═══════════════════════════════════════════════════════════════


class TestFaviconHash:

    def test_matches_shodan_recipe(self):
        """Hash must equal mmh3.hash(base64.encodebytes(content)) exactly."""
        content = b"\x89PNG\r\n\x1a\n" + b"fake-favicon-bytes" * 30
        expected = mmh3.hash(base64.encodebytes(content))
        assert WebReconTool._compute_favicon_hash(content) == expected

    def test_returns_signed_32bit_int(self):
        """MMH3 returns a signed 32-bit integer — important for storage and Shodan format."""
        h = WebReconTool._compute_favicon_hash(b"\x00\x01\x02\x03")
        assert isinstance(h, int)
        assert -(2**31) <= h < 2**31

    def test_identical_bytes_produce_identical_hash(self):
        content = b"identical content for hashing"
        assert WebReconTool._compute_favicon_hash(content) == \
               WebReconTool._compute_favicon_hash(content)

    def test_different_bytes_produce_different_hash(self):
        a = WebReconTool._compute_favicon_hash(b"version one")
        b = WebReconTool._compute_favicon_hash(b"version two")
        assert a != b

    def test_empty_bytes_still_hashes(self):
        """Empty bytes shouldn't crash — they hash to a stable value."""
        h = WebReconTool._compute_favicon_hash(b"")
        assert isinstance(h, int)


# ═══════════════════════════════════════════════════════════════
# 2. URL discovery
# ═══════════════════════════════════════════════════════════════


class TestFaviconDiscovery:

    def test_prefers_rel_icon_over_shortcut(self):
        html = '''
        <html><head>
            <link rel="shortcut icon" href="/legacy.ico">
            <link rel="icon" href="/preferred.png">
        </head></html>
        '''
        soup = BeautifulSoup(html, "html.parser")
        url = WebReconTool._discover_favicon_url(soup, "https://example.com/page")
        assert url == "https://example.com/preferred.png"

    def test_falls_back_to_apple_touch_icon(self):
        html = '<html><head><link rel="apple-touch-icon" href="/apple.png"></head></html>'
        soup = BeautifulSoup(html, "html.parser")
        url = WebReconTool._discover_favicon_url(soup, "https://example.com/")
        assert url == "https://example.com/apple.png"

    def test_fallback_to_root_favicon_ico(self):
        soup = BeautifulSoup("<html><head></head></html>", "html.parser")
        url = WebReconTool._discover_favicon_url(soup, "https://example.com/some/path")
        assert url == "https://example.com/favicon.ico"

    def test_resolves_relative_url_against_page(self):
        html = '<html><head><link rel="icon" href="../icons/favicon.png"></head></html>'
        soup = BeautifulSoup(html, "html.parser")
        url = WebReconTool._discover_favicon_url(soup, "https://example.com/sub/page")
        assert url == "https://example.com/icons/favicon.png"

    def test_resolves_absolute_url_unchanged(self):
        html = '<html><head><link rel="icon" href="https://cdn.elsewhere.com/icon.ico"></head></html>'
        soup = BeautifulSoup(html, "html.parser")
        url = WebReconTool._discover_favicon_url(soup, "https://example.com/")
        assert url == "https://cdn.elsewhere.com/icon.ico"

    def test_rejects_data_uri_and_falls_back(self):
        """data: URIs aren't fetchable — fall through to /favicon.ico."""
        html = '<html><head><link rel="icon" href="data:image/png;base64,iVBOR"></head></html>'
        soup = BeautifulSoup(html, "html.parser")
        url = WebReconTool._discover_favicon_url(soup, "https://example.com/")
        assert url == "https://example.com/favicon.ico"

    def test_rejects_invalid_scheme(self):
        html = '<html><head><link rel="icon" href="ftp://example.com/icon.ico"></head></html>'
        soup = BeautifulSoup(html, "html.parser")
        url = WebReconTool._discover_favicon_url(soup, "https://example.com/")
        # ftp:// is rejected, falls back
        assert url == "https://example.com/favicon.ico"

    def test_returns_none_when_page_url_has_no_origin(self):
        soup = BeautifulSoup("<html></html>", "html.parser")
        url = WebReconTool._discover_favicon_url(soup, "not-a-url")
        assert url is None


# ═══════════════════════════════════════════════════════════════
# 3. End-to-end _collect_favicon with mocked HTTP
# ═══════════════════════════════════════════════════════════════


class TestCollectFavicon:

    @pytest.fixture
    def tool(self):
        return WebReconTool(get_config())

    def _mock_client_factory(self, *, status_code: int, content: bytes, content_type: str = "image/x-icon"):
        """Return a callable that mimics httpx.Client(...) as a context manager."""
        class _FakeResponse:
            def __init__(self):
                self.status_code = status_code
                self.content = content
                self.headers = {"content-type": content_type}

        class _FakeClient:
            def __init__(self, **kwargs): pass
            def __enter__(self): return self
            def __exit__(self, *exc): return False
            def get(self, url): return _FakeResponse()

        return _FakeClient

    def test_successful_favicon_collected(self, tool):
        favicon_bytes = b"\x00\x00\x01\x00fake-ico-content"
        soup = BeautifulSoup('<html><head><link rel="icon" href="/favicon.ico"></head></html>', "html.parser")
        result = tool._collect_favicon(
            soup,
            "https://example.com/",
            client_factory=self._mock_client_factory(status_code=200, content=favicon_bytes),
        )
        assert result["url"] == "https://example.com/favicon.ico"
        assert result["status_code"] == 200
        assert result["size_bytes"] == len(favicon_bytes)
        assert result["mmh3_hash"] == mmh3.hash(base64.encodebytes(favicon_bytes))
        assert "error" not in result

    def test_404_returns_error_dict(self, tool):
        soup = BeautifulSoup('<html><head></head></html>', "html.parser")
        result = tool._collect_favicon(
            soup, "https://example.com/",
            client_factory=self._mock_client_factory(status_code=404, content=b""),
        )
        assert "error" in result
        assert "404" in result["error"]
        assert "mmh3_hash" not in result

    def test_empty_body_is_error(self, tool):
        soup = BeautifulSoup('<html><head></head></html>', "html.parser")
        result = tool._collect_favicon(
            soup, "https://example.com/",
            client_factory=self._mock_client_factory(status_code=200, content=b""),
        )
        assert result["error"] == "empty favicon body"
        assert "mmh3_hash" not in result

    def test_oversize_favicon_rejected(self, tool):
        """Favicons exceeding MAX_FAVICON_BYTES are not hashed."""
        from atlas.recon.web_recon import MAX_FAVICON_BYTES
        huge = b"x" * (MAX_FAVICON_BYTES + 1)
        soup = BeautifulSoup('<html><head></head></html>', "html.parser")
        result = tool._collect_favicon(
            soup, "https://example.com/",
            client_factory=self._mock_client_factory(status_code=200, content=huge),
        )
        assert result["error"] == "favicon exceeds size limit"
        assert "mmh3_hash" not in result

    def test_http_error_caught_gracefully(self, tool):
        import httpx
        class _ErroringClient:
            def __init__(self, **kwargs): pass
            def __enter__(self): return self
            def __exit__(self, *exc): return False
            def get(self, url): raise httpx.ConnectError("could not connect")

        soup = BeautifulSoup('<html><head></head></html>', "html.parser")
        result = tool._collect_favicon(
            soup, "https://example.com/", client_factory=_ErroringClient,
        )
        assert "error" in result
        assert "fetch failed" in result["error"]
        assert "ConnectError" in result["error"]


# ═══════════════════════════════════════════════════════════════
# 4. Repository: find_related_scans by favicon_hash
# ═══════════════════════════════════════════════════════════════


def _make_report(domain: str, verdict: Verdict = Verdict.CLEAN) -> ScanReport:
    return ScanReport(
        url=f"https://{domain}",
        domain=domain,
        final_verdict=verdict,
        tier_results=[TierResult(tier_name="t", flagged=False, confidence=0.0)],
        scanned_at=datetime.now(timezone.utc),
        scan_duration_ms=10,
        source=ScanSource.CLI,
    )


def _make_web_recon(domain: str, favicon_hash: int | None) -> ReconResult:
    """Build a web_recon ReconResult with a favicon hash (or None for missing favicon)."""
    favicon_data: dict
    if favicon_hash is None:
        favicon_data = {"error": "no favicon"}
    else:
        favicon_data = {
            "url": f"https://{domain}/favicon.ico",
            "status_code": 200,
            "size_bytes": 1024,
            "content_type": "image/x-icon",
            "mmh3_hash": favicon_hash,
        }
    return ReconResult(
        recon_type="web_recon",
        domain=domain,
        data={"favicon": favicon_data, "title": f"{domain} home"},
    )


class TestFindRelatedScansFavicon:

    @pytest.fixture
    def repo(self, tmp_path):
        return ScanRepository(db_path=str(tmp_path / "atlas.db"))

    def test_finds_scans_with_matching_favicon(self, repo):
        # Three scans, two share a favicon hash
        ids = {}
        for domain, fav in [("a.com", 12345), ("b.com", 12345), ("c.com", 99999)]:
            sid = repo.save_scan(_make_report(domain))
            repo.save_recon_results(sid, {"web_recon": _make_web_recon(domain, fav)})
            ids[domain] = sid

        related = repo.find_related_scans(
            exclude_scan_id=ids["a.com"],
            favicon_hash=12345,
        )

        matched_domains = {r["domain"] for r in related["favicon"]}
        assert matched_domains == {"b.com"}  # a.com excluded, c.com mismatched

    def test_excludes_scans_with_favicon_errors(self, repo):
        sid_a = repo.save_scan(_make_report("a.com"))
        repo.save_recon_results(sid_a, {"web_recon": _make_web_recon("a.com", 42)})

        sid_b = repo.save_scan(_make_report("b.com"))
        repo.save_recon_results(sid_b, {"web_recon": _make_web_recon("b.com", None)})

        related = repo.find_related_scans(exclude_scan_id=-1, favicon_hash=42)
        # b.com has an error dict (no mmh3_hash) → should not match
        assert len(related["favicon"]) == 1
        assert related["favicon"][0]["domain"] == "a.com"

    def test_no_favicon_hash_returns_empty_favicon_list(self, repo):
        """If favicon_hash=None is not passed, favicon results stay empty."""
        sid = repo.save_scan(_make_report("a.com"))
        repo.save_recon_results(sid, {"web_recon": _make_web_recon("a.com", 99)})

        related = repo.find_related_scans(exclude_scan_id=-1, ip="1.2.3.4")
        assert related["favicon"] == []

    def test_favicon_pivot_independent_of_ip_pivot(self, repo):
        """Favicon and IP pivots find different rows when stacked."""
        sid_a = repo.save_scan(_make_report("a.com"))
        repo.save_recon_results(sid_a, {
            "web_recon": _make_web_recon("a.com", 555),
            "ip_intel": ReconResult(
                recon_type="ip_intel", domain="a.com",
                data={"ip": "1.1.1.1", "geolocation": {"asn": "AS1"}},
            ),
        })
        sid_b = repo.save_scan(_make_report("b.com"))
        repo.save_recon_results(sid_b, {
            "web_recon": _make_web_recon("b.com", 555),  # same favicon
            "ip_intel": ReconResult(
                recon_type="ip_intel", domain="b.com",
                data={"ip": "2.2.2.2", "geolocation": {"asn": "AS2"}},  # different IP
            ),
        })

        related = repo.find_related_scans(
            exclude_scan_id=sid_a, favicon_hash=555, ip="1.1.1.1",
        )
        assert len(related["favicon"]) == 1  # b.com via favicon
        assert related["ip"] == []          # b.com is NOT on the same IP


# ═══════════════════════════════════════════════════════════════
# 5. CrossScanCorrelator favicon pivot extraction
# ═══════════════════════════════════════════════════════════════


class TestCrossScanFaviconPivot:

    def test_extracts_favicon_hash_from_context(self):
        report = _make_report("example.com")
        report.id = 1
        context = CorrelationContext(
            scan=report,
            recon={"web_recon": _make_web_recon("example.com", 42)},
        )
        assert CrossScanCorrelator._current_favicon_hash(context) == 42

    def test_returns_none_when_web_recon_missing(self):
        report = _make_report("example.com")
        report.id = 1
        context = CorrelationContext(scan=report, recon={})
        assert CrossScanCorrelator._current_favicon_hash(context) is None

    def test_returns_none_when_favicon_has_error(self):
        report = _make_report("example.com")
        report.id = 1
        context = CorrelationContext(
            scan=report,
            recon={"web_recon": _make_web_recon("example.com", None)},  # error path
        )
        assert CrossScanCorrelator._current_favicon_hash(context) is None

    def test_returns_none_when_hash_not_an_int(self):
        report = _make_report("example.com")
        report.id = 1
        context = CorrelationContext(
            scan=report,
            recon={"web_recon": ReconResult(
                recon_type="web_recon", domain="example.com",
                data={"favicon": {"mmh3_hash": "not-an-int", "url": "x"}},
            )},
        )
        assert CrossScanCorrelator._current_favicon_hash(context) is None

    def test_correlator_uses_favicon_when_available(self, tmp_path):
        """Full integration: when a stored scan shares a favicon, the correlator surfaces it."""
        repo = ScanRepository(db_path=str(tmp_path / "atlas.db"))

        # Seed: prior scan with favicon 777
        other_sid = repo.save_scan(_make_report("other.com"))
        repo.save_recon_results(other_sid, {"web_recon": _make_web_recon("other.com", 777)})

        # Current: new scan with the same favicon
        current = _make_report("current.com")
        current.id = repo.save_scan(current)
        repo.save_recon_results(current.id, {"web_recon": _make_web_recon("current.com", 777)})

        correlator = CrossScanCorrelator(config=get_config(), repo=repo)
        context = CorrelationContext(
            scan=current,
            recon={"web_recon": _make_web_recon("current.com", 777)},
        )
        result = correlator._correlate(context)

        favicon_findings = [f for f in result.findings if f["category"] == "favicon"]
        assert len(favicon_findings) == 1
        assert favicon_findings[0]["domain"] == "other.com"


# ═══════════════════════════════════════════════════════════════
# 6. CLI: atlas pivot favicon
# ═══════════════════════════════════════════════════════════════


class TestPivotFaviconCLI:

    @pytest.fixture
    def runner(self):
        return CliRunner()

    @pytest.fixture
    def patched_repo(self, tmp_path, monkeypatch):
        db_path = str(tmp_path / "atlas.db")
        repo = ScanRepository(db_path=db_path)
        import atlas.cli.main as cli_main
        monkeypatch.setattr(cli_main, "_repo", repo)
        return repo

    def test_pivot_finds_matches(self, runner, patched_repo):
        for d, h in [("a.com", 42), ("b.com", 42), ("c.com", 99)]:
            sid = patched_repo.save_scan(_make_report(d))
            patched_repo.save_recon_results(sid, {"web_recon": _make_web_recon(d, h)})

        result = runner.invoke(app, ["pivot", "favicon", "42"])
        assert result.exit_code == 0
        assert "a.com" in result.stdout
        assert "b.com" in result.stdout
        assert "c.com" not in result.stdout

    def test_pivot_no_matches_shows_empty_message(self, runner, patched_repo):
        result = runner.invoke(app, ["pivot", "favicon", "12345"])
        assert result.exit_code == 0
        assert "No scans" in result.stdout

    def test_pivot_json_output(self, runner, patched_repo):
        sid = patched_repo.save_scan(_make_report("evil.com"))
        patched_repo.save_recon_results(sid, {"web_recon": _make_web_recon("evil.com", 555)})

        result = runner.invoke(app, ["pivot", "favicon", "555", "--output", "json"])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["favicon_hash"] == 555
        assert len(data["matches"]) == 1
        assert data["matches"][0]["domain"] == "evil.com"

    def test_pivot_csv_output(self, runner, patched_repo):
        sid = patched_repo.save_scan(_make_report("evil.com"))
        patched_repo.save_recon_results(sid, {"web_recon": _make_web_recon("evil.com", 555)})

        result = runner.invoke(app, ["pivot", "favicon", "555", "--output", "csv"])
        assert result.exit_code == 0
        # CSV header + one row
        assert "scan_id" in result.stdout
        assert "evil.com" in result.stdout

    def test_invalid_output_rejected(self, runner, patched_repo):
        result = runner.invoke(app, ["pivot", "favicon", "1", "--output", "xml"])
        assert result.exit_code != 0


# ═══════════════════════════════════════════════════════════════
# 7. API: GET /api/v1/pivot/favicon/{hash}
# ═══════════════════════════════════════════════════════════════


class TestPivotFaviconAPI:

    @pytest.fixture
    def client(self):
        mock_repo = MagicMock()
        mock_repo.find_related_scans.return_value = {
            "ip": [], "asn": [], "registrar": [],
            "favicon": [
                {
                    "scan_id": 1, "domain": "evil.com", "url": "https://evil.com",
                    "verdict": "High Risk", "scanned_at": "2026-05-23T00:00:00Z",
                },
                {
                    "scan_id": 2, "domain": "another.evil.com", "url": "https://another.evil.com",
                    "verdict": "Medium Risk", "scanned_at": "2026-05-22T00:00:00Z",
                },
            ],
        }
        app_ = create_app()
        app_.dependency_overrides[dependencies.get_repo] = lambda: mock_repo
        app_.dependency_overrides[dependencies.get_atlas_config] = lambda: MagicMock()
        with TestClient(app_) as c:
            c.mock_repo = mock_repo  # expose for assertions
            yield c

    def test_returns_matches(self, client):
        response = client.get("/api/v1/pivot/favicon/12345")
        assert response.status_code == 200
        data = response.json()
        assert data["favicon_hash"] == 12345
        assert data["match_count"] == 2
        assert data["matches"][0]["domain"] == "evil.com"

    def test_passes_hash_to_repo(self, client):
        client.get("/api/v1/pivot/favicon/-1234567890")
        # The repo should have been called with that exact int
        _, kwargs = client.mock_repo.find_related_scans.call_args
        assert kwargs["favicon_hash"] == -1234567890

    def test_limit_query_param(self, client):
        client.get("/api/v1/pivot/favicon/42?limit=100")
        _, kwargs = client.mock_repo.find_related_scans.call_args
        assert kwargs["limit_per_category"] == 100

    def test_limit_validation_rejects_too_high(self, client):
        response = client.get("/api/v1/pivot/favicon/42?limit=9999")
        assert response.status_code == 422

    def test_rejects_non_integer_hash(self, client):
        response = client.get("/api/v1/pivot/favicon/not-an-int")
        assert response.status_code == 422
