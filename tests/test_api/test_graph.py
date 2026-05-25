"""
Tests for the graph API endpoint.

The endpoint walks BFS over scan pivots, so the tests build small scan
graphs in mocks and assert the resulting node/edge shape.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from atlas.api import dependencies
from atlas.api.main import create_app
from atlas.core.models import ReconResult, ScanReport, ScanSource, Verdict


# ── Helpers ──────────────────────────────────────────────────


def _scan_report(scan_id: int, domain: str, verdict: Verdict = Verdict.HIGH_RISK) -> ScanReport:
    """Build a minimal ScanReport for repo.get_scan() mocks."""
    return ScanReport(
        id=scan_id,
        url=f"https://{domain}",
        domain=domain,
        final_verdict=verdict,
        scanned_at=datetime(2026, 5, 24, 12, 0, 0, tzinfo=timezone.utc),
        scan_duration_ms=100,
        source=ScanSource.API,
        tier_results=[],
        correlations=[],
    )


def _recon_for(
    ip: str | None = None,
    asn: str | None = None,
    registrar: str | None = None,
    favicon_hash: int | None = None,
) -> dict[str, ReconResult]:
    """Build a recon dict suitable for repo.get_recon_results() mocks."""
    recon: dict[str, ReconResult] = {}
    if ip or asn:
        recon["ip_intel"] = ReconResult(
            recon_type="ip_intel",
            domain="x",
            data={
                "ip": ip,
                "geolocation": {"asn": asn} if asn else {},
            },
        )
    if registrar:
        recon["whois"] = ReconResult(
            recon_type="whois",
            domain="x",
            data={"registrar": registrar},
        )
    if favicon_hash is not None:
        recon["web_recon"] = ReconResult(
            recon_type="web_recon",
            domain="x",
            data={"favicon": {"mmh3_hash": favicon_hash}},
        )
    return recon


def _related_row(scan_id: int, domain: str, verdict: str = "Medium Risk") -> dict:
    """Build a row in the shape that find_related_scans returns."""
    return {
        "scan_id": scan_id,
        "domain": domain,
        "url": f"https://{domain}",
        "verdict": verdict,
        "scanned_at": "2026-05-23T00:00:00Z",
    }


@pytest.fixture
def mock_repo():
    """Mock ScanRepository — tests override individual methods as needed."""
    repo = MagicMock()
    # Default empty responses; tests override per case.
    repo.get_scan.return_value = None
    repo.get_recon_results.return_value = {}
    repo.find_related_scans.return_value = {
        "ip": [], "asn": [], "registrar": [], "favicon": [], "slash24": [],
    }
    return repo


@pytest.fixture
def client(mock_repo):
    """FastAPI TestClient with the repo dependency overridden."""
    app_ = create_app()
    app_.dependency_overrides[dependencies.get_repo] = lambda: mock_repo
    app_.dependency_overrides[dependencies.get_atlas_config] = lambda: MagicMock()
    with TestClient(app_) as c:
        c.mock_repo = mock_repo
        yield c


# ═════════════════════════════════════════════════════════════
# Validation & error responses
# ═════════════════════════════════════════════════════════════


class TestGraphRequestValidation:

    def test_unknown_scan_returns_404(self, client):
        client.mock_repo.get_scan.return_value = None
        response = client.get("/api/v1/graph/scan/999")
        assert response.status_code == 404
        assert "not found" in response.json()["detail"].lower()

    def test_invalid_scan_id_is_422(self, client):
        response = client.get("/api/v1/graph/scan/not-an-int")
        assert response.status_code == 422

    def test_depth_too_high_rejected(self, client):
        client.mock_repo.get_scan.return_value = _scan_report(1, "example.com")
        response = client.get("/api/v1/graph/scan/1?depth=5")
        assert response.status_code == 422

    def test_depth_zero_rejected(self, client):
        client.mock_repo.get_scan.return_value = _scan_report(1, "example.com")
        response = client.get("/api/v1/graph/scan/1?depth=0")
        assert response.status_code == 422

    def test_max_nodes_too_high_rejected(self, client):
        client.mock_repo.get_scan.return_value = _scan_report(1, "example.com")
        response = client.get("/api/v1/graph/scan/1?max_nodes=10000")
        assert response.status_code == 422


# ═════════════════════════════════════════════════════════════
# Root-only graphs (no pivots)
# ═════════════════════════════════════════════════════════════


class TestGraphRootOnly:

    def test_isolated_scan_returns_single_node(self, client):
        """A scan with no recon and no pivots should return only the root node."""
        client.mock_repo.get_scan.return_value = _scan_report(1, "example.com")
        client.mock_repo.get_recon_results.return_value = {}

        response = client.get("/api/v1/graph/scan/1")
        assert response.status_code == 200
        data = response.json()

        assert data["root_scan_id"] == 1
        assert data["stats"]["node_count"] == 1
        assert data["stats"]["edge_count"] == 0
        assert data["nodes"][0]["id"] == "1"
        assert data["nodes"][0]["type"] == "root"
        assert data["nodes"][0]["domain"] == "example.com"

    def test_root_with_no_neighbors(self, client):
        """A scan with recon but no related scans should still return one node."""
        client.mock_repo.get_scan.return_value = _scan_report(1, "example.com")
        client.mock_repo.get_recon_results.return_value = _recon_for(ip="1.2.3.4")
        client.mock_repo.find_related_scans.return_value = {
            "ip": [], "asn": [], "registrar": [], "favicon": [], "slash24": [],
        }

        response = client.get("/api/v1/graph/scan/1")
        data = response.json()
        assert data["stats"]["node_count"] == 1
        assert data["stats"]["edge_count"] == 0


# ═════════════════════════════════════════════════════════════
# Depth-1 graphs
# ═════════════════════════════════════════════════════════════


class TestGraphDepthOne:

    def test_single_pivot_creates_one_edge(self, client):
        """A scan that shares an IP with one other scan should yield 2 nodes, 1 edge."""
        client.mock_repo.get_scan.return_value = _scan_report(1, "root.com")
        client.mock_repo.get_recon_results.return_value = _recon_for(ip="1.2.3.4")
        client.mock_repo.find_related_scans.return_value = {
            "ip": [_related_row(2, "neighbor.com")],
            "asn": [], "registrar": [], "favicon": [], "slash24": [],
        }

        response = client.get("/api/v1/graph/scan/1?depth=1")
        data = response.json()

        assert data["stats"]["node_count"] == 2
        assert data["stats"]["edge_count"] == 1

        # Find the edge
        edge = data["edges"][0]
        assert edge["source"] == "1"
        assert edge["target"] == "2"
        assert edge["kind"] == "ip"
        assert edge["value"] == "1.2.3.4"

        # Both nodes present, root labelled
        node_ids = {n["id"] for n in data["nodes"]}
        assert node_ids == {"1", "2"}
        root_node = next(n for n in data["nodes"] if n["id"] == "1")
        assert root_node["type"] == "root"
        related_node = next(n for n in data["nodes"] if n["id"] == "2")
        assert related_node["type"] == "related"

    def test_multiple_pivot_kinds_to_same_target(self, client):
        """Two pivots (IP + /24) to the same target should produce 2 edges, 2 nodes."""
        client.mock_repo.get_scan.return_value = _scan_report(1, "root.com")
        client.mock_repo.get_recon_results.return_value = _recon_for(ip="1.2.3.4")
        # Same scan appears in both 'ip' and 'slash24' categories
        client.mock_repo.find_related_scans.return_value = {
            "ip": [_related_row(2, "neighbor.com")],
            "slash24": [_related_row(2, "neighbor.com")],
            "asn": [], "registrar": [], "favicon": [],
        }

        response = client.get("/api/v1/graph/scan/1?depth=1")
        data = response.json()

        assert data["stats"]["node_count"] == 2
        # Two distinct edge kinds between the same pair
        assert data["stats"]["edge_count"] == 2
        kinds = {e["kind"] for e in data["edges"]}
        assert kinds == {"ip", "slash24"}

    def test_edges_use_correct_pivot_values(self, client):
        """Each edge's value should reflect the pivot kind it represents."""
        client.mock_repo.get_scan.return_value = _scan_report(1, "root.com")
        client.mock_repo.get_recon_results.return_value = _recon_for(
            ip="10.0.0.5",
            asn="AS12345 Example",
            registrar="Example Registrar",
            favicon_hash=987654321,
        )
        client.mock_repo.find_related_scans.return_value = {
            "ip":        [_related_row(2, "a.com")],
            "asn":       [_related_row(3, "b.com")],
            "registrar": [_related_row(4, "c.com")],
            "favicon":   [_related_row(5, "d.com")],
            "slash24":   [_related_row(6, "e.com")],
        }

        response = client.get("/api/v1/graph/scan/1")
        data = response.json()

        values_by_kind = {e["kind"]: e["value"] for e in data["edges"]}
        assert values_by_kind["ip"] == "10.0.0.5"
        assert values_by_kind["asn"] == "AS12345 Example"
        assert values_by_kind["registrar"] == "Example Registrar"
        assert values_by_kind["favicon"] == "987654321"
        assert values_by_kind["slash24"] == "10.0.0.0/24"


# ═════════════════════════════════════════════════════════════
# Depth-2 graphs (BFS expansion)
# ═════════════════════════════════════════════════════════════


class TestGraphBFSExpansion:

    def test_depth_2_expands_neighbors(self, client):
        """Depth=2 should call get_recon_results for each new neighbor too."""
        client.mock_repo.get_scan.return_value = _scan_report(1, "root.com")

        # Different recon per scan id — depth-2 BFS asks each neighbor
        def recon_for_id(scan_id: int):
            return {
                1: _recon_for(ip="1.2.3.4"),
                2: _recon_for(ip="5.6.7.8"),
            }.get(scan_id, {})

        client.mock_repo.get_recon_results.side_effect = recon_for_id

        # Different neighbors per call — first call returns scan 2, second returns scan 3
        call_count = {"n": 0}

        def find_related(**kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                return {
                    "ip": [_related_row(2, "neighbor.com")],
                    "asn": [], "registrar": [], "favicon": [], "slash24": [],
                }
            return {
                "ip": [_related_row(3, "deep.com")],
                "asn": [], "registrar": [], "favicon": [], "slash24": [],
            }

        client.mock_repo.find_related_scans.side_effect = find_related

        response = client.get("/api/v1/graph/scan/1?depth=2")
        data = response.json()

        # All three scans should appear
        node_ids = {n["id"] for n in data["nodes"]}
        assert node_ids == {"1", "2", "3"}
        assert data["stats"]["depth_reached"] == 2

    def test_depth_2_stops_when_no_new_neighbors(self, client):
        """If depth 1's neighbors have no further pivots, BFS should stop early."""
        client.mock_repo.get_scan.return_value = _scan_report(1, "root.com")

        def recon_for_id(scan_id: int):
            # Only the root has any pivot attributes
            return _recon_for(ip="1.2.3.4") if scan_id == 1 else {}

        client.mock_repo.get_recon_results.side_effect = recon_for_id
        client.mock_repo.find_related_scans.return_value = {
            "ip": [_related_row(2, "neighbor.com")],
            "asn": [], "registrar": [], "favicon": [], "slash24": [],
        }

        response = client.get("/api/v1/graph/scan/1?depth=2")
        data = response.json()
        # 2 nodes because depth 2 found no new neighbors via scan 2
        assert data["stats"]["node_count"] == 2

    def test_cycle_does_not_duplicate_nodes(self, client):
        """If scan A pivots to B and B pivots back to A, A should appear only once."""
        client.mock_repo.get_scan.return_value = _scan_report(1, "root.com")
        client.mock_repo.get_recon_results.side_effect = lambda sid: _recon_for(ip="1.2.3.4")

        # First call (from scan 1): returns scan 2 as the IP-neighbor.
        # Second call (from scan 2): returns scan 1 as the IP-neighbor — the cycle.
        call_count = {"n": 0}

        def find_related(**kwargs):
            call_count["n"] += 1
            other_sid = 2 if call_count["n"] == 1 else 1
            other_domain = "neighbor.com" if other_sid == 2 else "root.com"
            return {
                "ip": [_related_row(other_sid, other_domain)],
                "asn": [], "registrar": [], "favicon": [], "slash24": [],
            }

        client.mock_repo.find_related_scans.side_effect = find_related

        response = client.get("/api/v1/graph/scan/1?depth=3")
        data = response.json()

        node_ids = [n["id"] for n in data["nodes"]]
        assert len(node_ids) == 2
        assert sorted(node_ids) == ["1", "2"]
        # Edge should be deduplicated — A↔B is one edge, not two even though
        # both ends pivoted to each other.
        assert data["stats"]["edge_count"] == 1


# ═════════════════════════════════════════════════════════════
# Node cap / truncation
# ═════════════════════════════════════════════════════════════


class TestGraphTruncation:

    def test_max_nodes_caps_results(self, client):
        """When max_nodes is hit, further candidates should be dropped."""
        client.mock_repo.get_scan.return_value = _scan_report(1, "root.com")
        client.mock_repo.get_recon_results.return_value = _recon_for(ip="1.2.3.4")
        # 20 neighbors but max_nodes=10 → only root + 9 neighbors fit
        client.mock_repo.find_related_scans.return_value = {
            "ip": [_related_row(i, f"n{i}.com") for i in range(2, 22)],
            "asn": [], "registrar": [], "favicon": [], "slash24": [],
        }

        response = client.get("/api/v1/graph/scan/1?max_nodes=10&limit_per_pivot=50")
        data = response.json()

        assert data["stats"]["node_count"] == 10
        assert data["stats"]["truncated"] is True


# ═════════════════════════════════════════════════════════════
# Query parameters reach the repo
# ═════════════════════════════════════════════════════════════


class TestGraphRepoCalls:

    def test_limit_per_pivot_passed_through(self, client):
        client.mock_repo.get_scan.return_value = _scan_report(1, "root.com")
        client.mock_repo.get_recon_results.return_value = _recon_for(ip="1.2.3.4")
        client.mock_repo.find_related_scans.return_value = {
            "ip": [], "asn": [], "registrar": [], "favicon": [], "slash24": [],
        }

        client.get("/api/v1/graph/scan/1?limit_per_pivot=25")

        _, kwargs = client.mock_repo.find_related_scans.call_args
        assert kwargs["limit_per_category"] == 25

    def test_pivot_args_extracted_from_recon(self, client):
        """The pivots passed to find_related_scans should match the recon data."""
        client.mock_repo.get_scan.return_value = _scan_report(1, "root.com")
        client.mock_repo.get_recon_results.return_value = _recon_for(
            ip="9.9.9.9",
            asn="AS999",
            registrar="Example LLC",
            favicon_hash=42,
        )

        client.get("/api/v1/graph/scan/1")
        _, kwargs = client.mock_repo.find_related_scans.call_args
        assert kwargs["ip"] == "9.9.9.9"
        assert kwargs["asn"] == "AS999"
        assert kwargs["registrar"] == "Example LLC"
        assert kwargs["favicon_hash"] == 42
        assert kwargs["slash24"] == "9.9.9"
