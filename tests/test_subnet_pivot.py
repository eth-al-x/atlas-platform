"""
Tests for the subnet-pivot work:
    - ScanRepository.find_scans_in_subnet (arbitrary-CIDR query)
    - CLI:  atlas pivot subnet <cidr>
    - API:  GET /api/v1/pivot/subnet?cidr=...

These pivot off the existing scan history. The complementary active PTR
enumeration is covered by test_ip_neighborhood.py — this file focuses on
the historical-query side.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from atlas.api import dependencies
from atlas.api.main import create_app
from atlas.cli.main import app as cli_app
from atlas.core.models import ReconResult, ScanReport, ScanSource, TierResult, Verdict
from atlas.storage.db import ScanRepository


# ═══════════════════════════════════════════════════════════════
# Fixtures + helpers
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


def _seed_scan(repo: ScanRepository, domain: str, ip: str | None) -> int:
    """Save a scan and (if ip given) attach an ip_intel recon row."""
    sid = repo.save_scan(_make_report(domain))
    if ip is not None:
        repo.save_recon_results(
            sid,
            {"ip_intel": ReconResult(recon_type="ip_intel", domain=domain, data={"ip": ip})},
        )
    return sid


@pytest.fixture
def repo(tmp_path):
    return ScanRepository(db_path=str(tmp_path / "atlas.db"))


# ═══════════════════════════════════════════════════════════════
# 1. find_scans_in_subnet — storage layer
# ═══════════════════════════════════════════════════════════════


class TestFindScansInSubnet:

    def test_slash24_matches_neighbors(self, repo):
        _seed_scan(repo, "a.com", "203.0.113.5")
        _seed_scan(repo, "b.com", "203.0.113.99")
        _seed_scan(repo, "c.com", "198.51.100.42")  # different /24

        matches = repo.find_scans_in_subnet("203.0.113.0/24")
        domains = {m["domain"] for m in matches}
        assert domains == {"a.com", "b.com"}
        # Each match has a matched_ip field
        assert all(m["matched_ip"] for m in matches)

    def test_slash16_widens_search(self, repo):
        _seed_scan(repo, "a.com", "203.0.113.5")
        _seed_scan(repo, "b.com", "203.0.99.99")    # different /24, same /16
        _seed_scan(repo, "c.com", "198.51.100.42")  # different /16

        matches = repo.find_scans_in_subnet("203.0.0.0/16")
        domains = {m["domain"] for m in matches}
        assert domains == {"a.com", "b.com"}

    def test_slash28_post_filters_to_exact_range(self, repo):
        """A /28 (16 IPs) requires Python post-filter since SQL only narrows by octet."""
        _seed_scan(repo, "a.com", "203.0.113.5")   # in 203.0.113.0/28
        _seed_scan(repo, "b.com", "203.0.113.50")  # NOT in /28 (above .15)
        _seed_scan(repo, "c.com", "203.0.113.10")  # in 203.0.113.0/28

        matches = repo.find_scans_in_subnet("203.0.113.0/28")
        domains = {m["domain"] for m in matches}
        assert domains == {"a.com", "c.com"}

    def test_exclude_scan_id(self, repo):
        sid_a = _seed_scan(repo, "a.com", "203.0.113.5")
        _seed_scan(repo, "b.com", "203.0.113.99")
        matches = repo.find_scans_in_subnet("203.0.113.0/24", exclude_scan_id=sid_a)
        domains = {m["domain"] for m in matches}
        assert domains == {"b.com"}

    def test_exclude_exact_ip(self, repo):
        """The 'exact IP' exclusion lets callers stack subnet pivot with exact-IP pivot."""
        _seed_scan(repo, "a.com", "203.0.113.5")
        _seed_scan(repo, "b.com", "203.0.113.99")
        matches = repo.find_scans_in_subnet(
            "203.0.113.0/24", exclude_exact_ip="203.0.113.5",
        )
        domains = {m["domain"] for m in matches}
        assert domains == {"b.com"}

    def test_no_matches_returns_empty_list(self, repo):
        _seed_scan(repo, "a.com", "10.0.0.1")
        matches = repo.find_scans_in_subnet("172.16.0.0/12")
        assert matches == []

    def test_invalid_cidr_returns_empty(self, repo):
        _seed_scan(repo, "a.com", "203.0.113.5")
        # Bad input shouldn't blow up — just return nothing
        assert repo.find_scans_in_subnet("not-a-cidr") == []
        assert repo.find_scans_in_subnet("999.999.999.999/24") == []

    def test_ipv6_cidr_returns_empty(self, repo):
        """IPv6 is parsed but unsupported (ATLAS resolves only A records)."""
        _seed_scan(repo, "a.com", "203.0.113.5")
        assert repo.find_scans_in_subnet("2001:db8::/32") == []

    def test_scans_without_ip_recon_ignored(self, repo):
        """A scan with no ip_intel recon shouldn't appear in subnet results."""
        _seed_scan(repo, "no-recon.com", None)             # scan exists but no ip_intel
        _seed_scan(repo, "with-recon.com", "203.0.113.5")  # has ip_intel
        matches = repo.find_scans_in_subnet("0.0.0.0/0")   # match all
        domains = {m["domain"] for m in matches}
        assert domains == {"with-recon.com"}

    def test_limit_caps_returned_rows(self, repo):
        for i in range(10):
            _seed_scan(repo, f"host{i}.com", f"203.0.113.{i+1}")
        matches = repo.find_scans_in_subnet("203.0.113.0/24", limit=3)
        assert len(matches) == 3

    def test_results_ordered_newest_first(self, repo):
        """SQL orders by scanned_at DESC — newer scans surface first."""
        sid_a = _seed_scan(repo, "a.com", "203.0.113.5")
        sid_b = _seed_scan(repo, "b.com", "203.0.113.10")
        # b was inserted second so should appear first
        matches = repo.find_scans_in_subnet("203.0.113.0/24")
        assert matches[0]["scan_id"] == sid_b
        assert matches[1]["scan_id"] == sid_a


# ═══════════════════════════════════════════════════════════════
# 2. CLI: atlas pivot subnet
# ═══════════════════════════════════════════════════════════════


class TestPivotSubnetCLI:

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

    def test_finds_subnet_matches(self, runner, patched_repo):
        _seed_scan(patched_repo, "a.com", "203.0.113.5")
        _seed_scan(patched_repo, "b.com", "203.0.113.99")

        result = runner.invoke(cli_app, ["pivot", "subnet", "203.0.113.0/24"])
        assert result.exit_code == 0
        assert "a.com" in result.stdout
        assert "b.com" in result.stdout

    def test_no_matches_shows_empty_message(self, runner, patched_repo):
        result = runner.invoke(cli_app, ["pivot", "subnet", "10.0.0.0/24"])
        assert result.exit_code == 0
        assert "No scans" in result.stdout

    def test_invalid_cidr_rejected(self, runner, patched_repo):
        result = runner.invoke(cli_app, ["pivot", "subnet", "not-a-cidr"])
        assert result.exit_code == 2  # validation exit
        assert "Invalid CIDR" in result.stdout

    def test_ipv6_rejected(self, runner, patched_repo):
        result = runner.invoke(cli_app, ["pivot", "subnet", "2001:db8::/32"])
        assert result.exit_code == 2
        assert "IPv6" in result.stdout

    def test_json_output(self, runner, patched_repo):
        _seed_scan(patched_repo, "evil.com", "203.0.113.5")
        result = runner.invoke(
            cli_app, ["pivot", "subnet", "203.0.113.0/24", "--output", "json"],
        )
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["cidr"] == "203.0.113.0/24"
        assert data["match_count"] == 1
        assert data["matches"][0]["domain"] == "evil.com"

    def test_csv_output(self, runner, patched_repo):
        _seed_scan(patched_repo, "evil.com", "203.0.113.5")
        result = runner.invoke(
            cli_app, ["pivot", "subnet", "203.0.113.0/24", "--output", "csv"],
        )
        assert result.exit_code == 0
        # Should have header line + one data row
        assert "scan_id" in result.stdout
        assert "evil.com" in result.stdout
        assert "203.0.113.5" in result.stdout

    def test_limit_flag(self, runner, patched_repo):
        for i in range(5):
            _seed_scan(patched_repo, f"host{i}.com", f"203.0.113.{i+1}")

        result = runner.invoke(
            cli_app, ["pivot", "subnet", "203.0.113.0/24",
                      "--limit", "2", "--output", "json"],
        )
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert len(data["matches"]) == 2

    def test_invalid_output_format_rejected(self, runner, patched_repo):
        result = runner.invoke(
            cli_app, ["pivot", "subnet", "1.0.0.0/24", "--output", "xml"],
        )
        assert result.exit_code != 0


# ═══════════════════════════════════════════════════════════════
# 3. API: GET /api/v1/pivot/subnet
# ═══════════════════════════════════════════════════════════════


class TestPivotSubnetAPI:

    @pytest.fixture
    def mock_repo(self):
        repo = MagicMock()
        repo.find_scans_in_subnet.return_value = [
            {
                "scan_id": 1, "domain": "evil.com", "url": "https://evil.com",
                "verdict": "High Risk", "scanned_at": "2026-05-23T00:00:00Z",
                "matched_ip": "203.0.113.5",
            },
            {
                "scan_id": 2, "domain": "lookalike.com", "url": "https://lookalike.com",
                "verdict": "Medium Risk", "scanned_at": "2026-05-22T00:00:00Z",
                "matched_ip": "203.0.113.10",
            },
        ]
        return repo

    @pytest.fixture
    def client(self, mock_repo):
        app = create_app()
        app.dependency_overrides[dependencies.get_repo] = lambda: mock_repo
        app.dependency_overrides[dependencies.get_atlas_config] = lambda: MagicMock()
        with TestClient(app) as c:
            c.mock_repo = mock_repo
            yield c

    def test_returns_matches(self, client):
        response = client.get("/api/v1/pivot/subnet?cidr=203.0.113.0/24")
        assert response.status_code == 200
        data = response.json()
        assert data["cidr"] == "203.0.113.0/24"
        assert data["match_count"] == 2
        assert data["address_count"] == 256  # /24 has 256 addresses
        assert data["matches"][0]["domain"] == "evil.com"

    def test_passes_cidr_to_repo(self, client):
        client.get("/api/v1/pivot/subnet?cidr=10.0.0.0/16")
        args, _ = client.mock_repo.find_scans_in_subnet.call_args
        assert args[0] == "10.0.0.0/16"

    def test_invalid_cidr_returns_400(self, client):
        response = client.get("/api/v1/pivot/subnet?cidr=not-a-cidr")
        assert response.status_code == 400
        assert "invalid" in response.json()["detail"].lower()

    def test_ipv6_returns_400(self, client):
        response = client.get("/api/v1/pivot/subnet?cidr=2001:db8::/32")
        assert response.status_code == 400
        assert "ipv6" in response.json()["detail"].lower()

    def test_missing_cidr_returns_422(self, client):
        """CIDR is required — missing it triggers Pydantic validation."""
        response = client.get("/api/v1/pivot/subnet")
        assert response.status_code == 422

    def test_limit_query_param(self, client):
        client.get("/api/v1/pivot/subnet?cidr=10.0.0.0/24&limit=100")
        args, _ = client.mock_repo.find_scans_in_subnet.call_args
        # Positional: cidr, exclude_scan_id, exclude_exact_ip, limit
        assert args[3] == 100

    def test_limit_validation_rejects_too_high(self, client):
        response = client.get("/api/v1/pivot/subnet?cidr=10.0.0.0/24&limit=9999")
        assert response.status_code == 422

    def test_address_count_reflects_cidr_size(self, client):
        response = client.get("/api/v1/pivot/subnet?cidr=10.0.0.0/16")
        assert response.json()["address_count"] == 65536
