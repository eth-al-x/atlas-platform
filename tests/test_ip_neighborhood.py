"""
Tests for atlas.recon.ip_neighborhood and the cross-scan /24 pivot.

Coverage:
    1. Target resolution (domain → IP, literal IP, IPv6 rejection)
    2. CIDR-bit coercion (default, clamp, garbage input)
    3. PTR-to-apex reduction
    4. End-to-end _run with mocked PTR/resolve calls
    5. _slash24_prefix helper
    6. Repository: find_related_scans slash24 GLOB pivot
    7. CrossScanCorrelator surfaces /24 matches
    8. CLI: atlas recon neighbors
    9. API: GET /api/v1/recon/neighbors/{domain}
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from atlas.api import dependencies
from atlas.api.main import create_app
from atlas.cli.main import app as cli_app
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
from atlas.recon.ip_neighborhood import (
    DEFAULT_CIDR_BITS,
    MAX_CIDR_BITS,
    MIN_CIDR_BITS,
    IPNeighborhoodReconTool,
)
from atlas.storage.db import ScanRepository


@pytest.fixture
def tool():
    return IPNeighborhoodReconTool(get_config())


# ═══════════════════════════════════════════════════════════════
# 1. Target resolution
# ═══════════════════════════════════════════════════════════════


class TestTargetResolution:

    def test_ip_literal_returns_unchanged(self):
        assert IPNeighborhoodReconTool._resolve_target_ip("1.2.3.4") == "1.2.3.4"

    def test_domain_is_resolved(self):
        with patch("socket.gethostbyname", return_value="93.184.216.34"):
            assert IPNeighborhoodReconTool._resolve_target_ip("example.com") == "93.184.216.34"

    def test_resolution_failure_returns_none(self):
        import socket
        with patch("socket.gethostbyname", side_effect=socket.gaierror()):
            assert IPNeighborhoodReconTool._resolve_target_ip("nope.invalid") is None


# ═══════════════════════════════════════════════════════════════
# 2. CIDR-bit coercion
# ═══════════════════════════════════════════════════════════════


class TestCidrCoercion:

    def test_none_returns_default(self):
        assert IPNeighborhoodReconTool._coerce_cidr_bits(None) == DEFAULT_CIDR_BITS

    def test_valid_value_passes_through(self):
        assert IPNeighborhoodReconTool._coerce_cidr_bits(26) == 26

    def test_below_min_is_clamped(self):
        assert IPNeighborhoodReconTool._coerce_cidr_bits(8) == MIN_CIDR_BITS

    def test_above_max_is_clamped(self):
        assert IPNeighborhoodReconTool._coerce_cidr_bits(32) == MAX_CIDR_BITS

    def test_garbage_returns_default(self):
        assert IPNeighborhoodReconTool._coerce_cidr_bits("not-a-number") == DEFAULT_CIDR_BITS
        assert IPNeighborhoodReconTool._coerce_cidr_bits([1, 2]) == DEFAULT_CIDR_BITS

    def test_numeric_string_is_accepted(self):
        assert IPNeighborhoodReconTool._coerce_cidr_bits("26") == 26


# ═══════════════════════════════════════════════════════════════
# 3. PTR-to-apex reduction
# ═══════════════════════════════════════════════════════════════


class TestPtrToApex:

    def test_basic_two_part(self):
        assert IPNeighborhoodReconTool._ptr_to_apex("example.com") == "example.com"

    def test_strips_trailing_dot(self):
        assert IPNeighborhoodReconTool._ptr_to_apex("example.com.") == "example.com"

    def test_keeps_last_two_labels(self):
        assert IPNeighborhoodReconTool._ptr_to_apex(
            "ec2-1-2-3-4.compute.amazonaws.com"
        ) == "amazonaws.com"

    def test_single_label_returns_unchanged(self):
        assert IPNeighborhoodReconTool._ptr_to_apex("localhost") == "localhost"


# ═══════════════════════════════════════════════════════════════
# 4. End-to-end _run (mocked DNS)
# ═══════════════════════════════════════════════════════════════


class TestEndToEnd:

    def test_run_handles_unresolvable_target(self, tool):
        with patch.object(tool, "_resolve_target_ip", return_value=None):
            result = tool.run("nonexistent.invalid")
        assert result.data["error"] == "could not resolve target to an IP address"
        assert result.data["neighbors"] == []

    def test_run_rejects_ipv6(self, tool):
        with patch.object(tool, "_resolve_target_ip", return_value="2001:db8::1"):
            result = tool.run("ipv6host.example")
        assert "IPv6 not supported" in result.data["error"]

    def test_run_full_path_with_ptrs(self, tool):
        """Full path: resolution → PTR sweep → structured output."""
        # Target IP and its 14-IP neighborhood (a /28 = 16 IPs including network/broadcast)
        target_ip = "1.2.3.4"

        # Return PTRs only for the target and two neighbors
        mock_ptrs = {
            "1.2.3.4": "host-4.example.com",
            "1.2.3.5": "host-5.example.com",
            "1.2.3.7": "evil-lookalike.io",
        }

        with patch.object(tool, "_resolve_target_ip", return_value=target_ip), \
             patch.object(tool, "_concurrent_ptr_lookup", return_value=mock_ptrs):
            result = tool.run("example.com", cidr_bits=28)

        data = result.data
        assert data["ip"] == "1.2.3.4"
        assert data["cidr"] == "1.2.3.0/28"
        assert data["cidr_bits"] == 28
        assert data["neighborhood_size"] == 16
        # Only the 3 IPs with PTRs should appear in the neighbors list
        assert len(data["neighbors"]) == 3
        # The target itself should be flagged with self=True
        target_entry = next(n for n in data["neighbors"] if n["ip"] == "1.2.3.4")
        assert target_entry["self"] is True
        assert target_entry["ptr"] == "host-4.example.com"
        # And one of the neighbors must NOT be self
        other_entry = next(n for n in data["neighbors"] if n["ip"] == "1.2.3.5")
        assert other_entry["self"] is False
        # Apex domains rolled up
        assert "example.com" in data["summary"]["unique_domains"]
        assert "evil-lookalike.io" in data["summary"]["unique_domains"]


# ═══════════════════════════════════════════════════════════════
# 5. _slash24_prefix helper
# ═══════════════════════════════════════════════════════════════


class TestSlash24Prefix:

    def test_ipv4_yields_three_octets(self):
        assert CrossScanCorrelator._slash24_prefix("1.2.3.4") == "1.2.3"

    def test_empty_returns_none(self):
        assert CrossScanCorrelator._slash24_prefix("") is None

    def test_ipv6_returns_none(self):
        assert CrossScanCorrelator._slash24_prefix("2001:db8::1") is None

    def test_malformed_returns_none(self):
        assert CrossScanCorrelator._slash24_prefix("not.an.ip") is None
        assert CrossScanCorrelator._slash24_prefix("1.2.3") is None
        assert CrossScanCorrelator._slash24_prefix("1.2.3.4.5") is None

    def test_out_of_range_octet_returns_none(self):
        assert CrossScanCorrelator._slash24_prefix("1.2.3.999") is None
        assert CrossScanCorrelator._slash24_prefix("-1.2.3.4") is None


# ═══════════════════════════════════════════════════════════════
# 6. Repository: find_related_scans slash24 GLOB pivot
# ═══════════════════════════════════════════════════════════════


def _make_report(domain: str, verdict: Verdict = Verdict.CLEAN) -> ScanReport:
    return ScanReport(
        url=f"https://{domain}",
        domain=domain,
        final_verdict=verdict,
        tier_results=[TierResult(tier_name="t", flagged=False, confidence=0.0)],
        scanned_at=datetime.now(timezone.utc),
        scan_duration_ms=5,
        source=ScanSource.CLI,
    )


def _make_ip_recon(domain: str, ip: str, asn: str = "AS1") -> ReconResult:
    return ReconResult(
        recon_type="ip_intel",
        domain=domain,
        data={"ip": ip, "geolocation": {"asn": asn}},
    )


class TestSlash24Pivot:

    @pytest.fixture
    def repo(self, tmp_path):
        return ScanRepository(db_path=str(tmp_path / "atlas.db"))

    def test_finds_scans_in_same_slash24(self, repo):
        # Three scans: two in 1.2.3.0/24, one in 9.9.9.0/24
        for domain, ip in [
            ("a.com", "1.2.3.10"),
            ("b.com", "1.2.3.50"),
            ("c.com", "9.9.9.9"),
        ]:
            sid = repo.save_scan(_make_report(domain))
            repo.save_recon_results(sid, {"ip_intel": _make_ip_recon(domain, ip)})

        related = repo.find_related_scans(
            exclude_scan_id=-1,
            slash24="1.2.3",
        )
        matched_domains = {r["domain"] for r in related["slash24"]}
        assert matched_domains == {"a.com", "b.com"}
        assert all(r["matched_value"].startswith("1.2.3.") for r in related["slash24"])

    def test_excludes_exact_ip_match_to_avoid_double_counting(self, repo):
        """When both ip and slash24 are passed, the /24 pivot must exclude
        the exact-IP row so it doesn't appear in both buckets."""
        for domain, ip in [
            ("exact.com", "1.2.3.4"),   # exact IP match
            ("nearby.com", "1.2.3.99"), # same /24 but different IP
        ]:
            sid = repo.save_scan(_make_report(domain))
            repo.save_recon_results(sid, {"ip_intel": _make_ip_recon(domain, ip)})

        related = repo.find_related_scans(
            exclude_scan_id=-1,
            ip="1.2.3.4",
            slash24="1.2.3",
        )
        # exact.com is in 'ip' bucket
        assert {r["domain"] for r in related["ip"]} == {"exact.com"}
        # nearby.com is in 'slash24' bucket, exact.com must NOT be (else duplicate)
        assert {r["domain"] for r in related["slash24"]} == {"nearby.com"}

    def test_glob_pattern_does_not_overmatch(self, repo):
        """1.2.3 GLOB should not match 1.2.30 or 11.2.3 — verify boundary behavior."""
        for domain, ip in [
            ("inside.com", "1.2.3.99"),
            ("outside-a.com", "1.2.30.5"),   # /24 prefix '1.2.30' is different
            ("outside-b.com", "11.2.3.5"),   # leading '1' isn't a substring match
        ]:
            sid = repo.save_scan(_make_report(domain))
            repo.save_recon_results(sid, {"ip_intel": _make_ip_recon(domain, ip)})

        related = repo.find_related_scans(exclude_scan_id=-1, slash24="1.2.3")
        matched = {r["domain"] for r in related["slash24"]}
        assert matched == {"inside.com"}

    def test_no_slash24_arg_yields_empty(self, repo):
        sid = repo.save_scan(_make_report("a.com"))
        repo.save_recon_results(sid, {"ip_intel": _make_ip_recon("a.com", "1.2.3.4")})
        related = repo.find_related_scans(exclude_scan_id=-1, ip="9.9.9.9")
        assert related["slash24"] == []


# ═══════════════════════════════════════════════════════════════
# 7. CrossScanCorrelator surfaces /24 matches
# ═══════════════════════════════════════════════════════════════


class TestCorrelatorSlash24Integration:

    def test_correlator_surfaces_slash24_findings(self, tmp_path):
        repo = ScanRepository(db_path=str(tmp_path / "atlas.db"))

        # Prior scan in same /24 but different exact IP
        other_sid = repo.save_scan(_make_report("nearby.com"))
        repo.save_recon_results(
            other_sid,
            {"ip_intel": _make_ip_recon("nearby.com", "1.2.3.99", asn="AS999")},
        )

        # Current scan
        current = _make_report("current.com")
        current.id = repo.save_scan(current)
        repo.save_recon_results(
            current.id,
            {"ip_intel": _make_ip_recon("current.com", "1.2.3.4", asn="AS999")},
        )

        correlator = CrossScanCorrelator(config=get_config(), repo=repo)
        context = CorrelationContext(
            scan=current,
            recon={"ip_intel": _make_ip_recon("current.com", "1.2.3.4", asn="AS999")},
        )
        result = correlator._correlate(context)

        # The slash24 finding should be present
        slash24_findings = [f for f in result.findings if f["category"] == "slash24"]
        assert len(slash24_findings) == 1
        assert slash24_findings[0]["domain"] == "nearby.com"

        # Pivots dict exposes the prefix used
        assert result.data["pivots"]["slash24"] == "1.2.3"


# ═══════════════════════════════════════════════════════════════
# 8. CLI: atlas recon neighbors
# ═══════════════════════════════════════════════════════════════


class TestNeighborsCLI:

    @pytest.fixture
    def runner(self):
        return CliRunner()

    def test_renders_neighborhood_results(self, runner):
        fake_result = ReconResult(
            recon_type="ip_neighborhood",
            domain="example.com",
            data={
                "ip": "1.2.3.4",
                "cidr": "1.2.3.0/28",
                "cidr_bits": 28,
                "neighborhood_size": 16,
                "neighbors": [
                    {"ip": "1.2.3.4", "ptr": "host-4.example.com", "self": True},
                    {"ip": "1.2.3.5", "ptr": "host-5.example.com", "self": False},
                ],
                "summary": {
                    "neighbors_found": 2,
                    "ips_probed": 14,
                    "unique_domains": ["example.com"],
                },
            },
        )
        with patch("atlas.recon.ip_neighborhood.IPNeighborhoodReconTool") as MockTool:
            MockTool.return_value.run.return_value = fake_result
            result = runner.invoke(cli_app, ["recon", "neighbors", "example.com"])

        assert result.exit_code == 0
        assert "1.2.3.4" in result.stdout
        assert "1.2.3.0/28" in result.stdout
        assert "host-5.example.com" in result.stdout
        assert "self" in result.stdout                 # marker text for target row

    def test_handles_unresolvable_target(self, runner):
        fake_result = ReconResult(
            recon_type="ip_neighborhood",
            domain="nonexistent.invalid",
            data={
                "ip": None, "cidr": None, "neighbors": [],
                "error": "could not resolve target to an IP address",
            },
        )
        with patch("atlas.recon.ip_neighborhood.IPNeighborhoodReconTool") as MockTool:
            MockTool.return_value.run.return_value = fake_result
            result = runner.invoke(cli_app, ["recon", "neighbors", "nonexistent.invalid"])

        assert result.exit_code == 0
        assert "could not resolve" in result.stdout

    def test_passes_cidr_option_through(self, runner):
        fake_result = ReconResult(
            recon_type="ip_neighborhood",
            domain="example.com",
            data={"ip": "1.2.3.4", "cidr": "1.2.3.0/25", "cidr_bits": 25,
                  "neighborhood_size": 128, "neighbors": [],
                  "summary": {"neighbors_found": 0, "ips_probed": 126, "unique_domains": []}},
        )
        with patch("atlas.recon.ip_neighborhood.IPNeighborhoodReconTool") as MockTool:
            MockTool.return_value.run.return_value = fake_result
            result = runner.invoke(cli_app, ["recon", "neighbors", "example.com", "--cidr", "25"])

        # The tool was instantiated and run() was called with cidr_bits=25
        MockTool.return_value.run.assert_called_once()
        args, kwargs = MockTool.return_value.run.call_args
        assert kwargs.get("cidr_bits") == 25 or 25 in args

    def test_rejects_out_of_range_cidr(self, runner):
        result = runner.invoke(cli_app, ["recon", "neighbors", "example.com", "--cidr", "8"])
        assert result.exit_code != 0


# ═══════════════════════════════════════════════════════════════
# 9. API: GET /api/v1/recon/neighbors/{domain}
# ═══════════════════════════════════════════════════════════════


class TestNeighborsAPI:

    @pytest.fixture
    def client(self):
        mock_tool = MagicMock()
        mock_tool.run.return_value = ReconResult(
            recon_type="ip_neighborhood",
            domain="example.com",
            data={
                "ip": "1.2.3.4",
                "cidr": "1.2.3.0/28",
                "cidr_bits": 28,
                "neighborhood_size": 16,
                "neighbors": [
                    {"ip": "1.2.3.4", "ptr": "host-4.example.com", "self": True},
                ],
                "summary": {"neighbors_found": 1, "ips_probed": 14,
                            "unique_domains": ["example.com"]},
            },
        )
        mock_tools = {"ip_neighborhood": mock_tool}

        app_ = create_app()
        import atlas.api.routes.recon as recon_module
        recon_module._tools = mock_tools
        app_.dependency_overrides[dependencies.get_atlas_config] = lambda: MagicMock()
        app_.dependency_overrides[dependencies.get_pipeline] = lambda: MagicMock()
        app_.dependency_overrides[dependencies.get_repo] = lambda: MagicMock()

        with TestClient(app_) as c:
            c.mock_tool = mock_tool
            yield c

        recon_module._tools = None

    def test_endpoint_returns_neighborhood_data(self, client):
        response = client.get("/api/v1/recon/neighbors/example.com")
        assert response.status_code == 200
        data = response.json()
        assert data["result"]["recon_type"] == "ip_neighborhood"
        assert data["result"]["data"]["cidr"] == "1.2.3.0/28"

    def test_cidr_bits_passed_to_tool(self, client):
        client.get("/api/v1/recon/neighbors/example.com?cidr_bits=26")
        args, kwargs = client.mock_tool.run.call_args
        assert kwargs.get("cidr_bits") == 26

    def test_default_cidr_when_omitted(self, client):
        client.get("/api/v1/recon/neighbors/example.com")
        args, kwargs = client.mock_tool.run.call_args
        assert kwargs.get("cidr_bits") == 28

    def test_rejects_out_of_range_cidr_bits(self, client):
        for bad in (8, 23, 31, 100):
            response = client.get(f"/api/v1/recon/neighbors/example.com?cidr_bits={bad}")
            assert response.status_code == 422
