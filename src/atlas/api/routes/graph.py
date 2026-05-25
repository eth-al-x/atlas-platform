"""
atlas.api.routes.graph
Graph endpoint — returns a node-link graph of scans related to a root scan.

GET /graph/scan/{scan_id}    Build a graph centered on this scan

Walks BFS from the root using the cross-scan correlator's pivot signals
(shared IP, ASN, registrar, favicon hash, /24). depth=1 returns the root
plus its immediate neighbors; depth=2 expands each of those one more hop;
depth=3 is available but throttled — graphs get unreadable fast.

This endpoint is the data source for the dashboard's interactive graph
view. It returns Cytoscape-compatible nodes and edges in a single
response, sized for direct rendering without further client-side
processing.

The shape is intentionally minimal — domain and verdict for nodes, kind
and matched value for edges — so the frontend stays focused on layout
and interaction rather than ad-hoc transformations.
"""

from __future__ import annotations

import asyncio
import logging
from functools import partial
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from atlas.api.dependencies import get_repo
from atlas.correlate.cross_scan import CrossScanCorrelator
from atlas.storage.db import ScanRepository

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/graph", tags=["Graph"])


# Categories the cross-scan correlator emits and we render as edges.
# Order matters for stable JSON output; the frontend doesn't care.
_PIVOT_CATEGORIES = ("ip", "asn", "registrar", "favicon", "slash24")


@router.get(
    "/scan/{scan_id}",
    summary="Graph of scans related to a root scan",
    description=(
        "Build a node-link graph centered on the given scan by walking "
        "the cross-scan pivot signals (shared IP, ASN, registrar, favicon "
        "hash, /24 prefix). Returns Cytoscape-compatible nodes and edges.\n\n"
        "**depth=1** — root plus direct neighbors. Recommended default.\n"
        "**depth=2** — each neighbor expanded one more hop.\n"
        "**depth=3** — full hairball; only useful for small datasets.\n\n"
        "**max_nodes** caps the total graph size; further candidates are "
        "dropped and `stats.truncated` is set to true."
    ),
)
async def get_scan_graph(
    scan_id: int,
    depth: int = Query(default=1, ge=1, le=3, description="BFS depth from the root."),
    max_nodes: int = Query(
        default=100, ge=10, le=500,
        description="Maximum total nodes to return.",
    ),
    limit_per_pivot: int = Query(
        default=10, ge=1, le=50,
        description="Maximum related scans returned per pivot category, per frontier node.",
    ),
    repo: ScanRepository = Depends(get_repo),
) -> dict:
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(
        None,
        partial(_build_graph, repo, scan_id, depth, max_nodes, limit_per_pivot),
    )
    if result is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found.")
    return result


# ── Graph construction ────────────────────────────────────────


def _build_graph(
    repo: ScanRepository,
    root_scan_id: int,
    depth: int,
    max_nodes: int,
    limit_per_pivot: int,
) -> dict | None:
    """
    BFS from root_scan_id, expanding via cross-scan pivots up to `depth` hops.

    Returns the assembled graph payload, or None if the root scan doesn't exist.
    """
    root_report = repo.get_scan(root_scan_id)
    if root_report is None:
        return None

    # Nodes are keyed by scan_id for O(1) "already seen" checks
    nodes_by_id: dict[int, dict[str, Any]] = {
        root_scan_id: _node_payload(
            scan_id=root_scan_id,
            domain=root_report.domain,
            verdict=root_report.final_verdict.value,
            scanned_at=root_report.scanned_at.isoformat(),
            is_root=True,
        ),
    }

    # Edges deduped by (unordered pair of node ids, kind) so a back-pivot
    # from B → A doesn't appear as a separate edge from A → B
    edges: list[dict[str, Any]] = []
    edge_keys: set[tuple[frozenset[int], str]] = set()

    frontier: list[int] = [root_scan_id]
    truncated = False
    depth_reached = 0

    for _ in range(depth):
        next_frontier: list[int] = []

        for sid in frontier:
            # We need this scan's pivot attributes to find its neighbors
            recon = repo.get_recon_results(sid)
            pivots = _extract_pivots(recon)
            if not any(v is not None for v in pivots.values()):
                continue

            related = repo.find_related_scans(
                exclude_scan_id=sid,
                ip=pivots["ip"],
                asn=pivots["asn"],
                registrar=pivots["registrar"],
                favicon_hash=pivots["favicon_hash"],
                slash24=pivots["slash24"],
                limit_per_category=limit_per_pivot,
            )

            for category in _PIVOT_CATEGORIES:
                matches = related.get(category, [])
                pivot_value = _pivot_display_value(category, pivots)

                for match in matches:
                    match_sid = int(match["scan_id"])

                    # Defensive: skip self-loops. find_related_scans should
                    # exclude the caller, but if a malformed row comes back
                    # we don't want frozenset({sid, sid}) collapsing to a
                    # one-element key that bypasses normal edge dedup.
                    if match_sid == sid:
                        continue

                    # Add node if new and under the cap
                    if match_sid not in nodes_by_id:
                        if len(nodes_by_id) >= max_nodes:
                            truncated = True
                            continue
                        nodes_by_id[match_sid] = _node_payload(
                            scan_id=match_sid,
                            domain=match["domain"],
                            verdict=match["verdict"],
                            scanned_at=match["scanned_at"],
                            is_root=False,
                        )
                        next_frontier.append(match_sid)

                    # Dedupe edges by unordered pair + kind
                    edge_key = (frozenset({sid, match_sid}), category)
                    if edge_key in edge_keys:
                        continue
                    edge_keys.add(edge_key)
                    edges.append({
                        "source": str(sid),
                        "target": str(match_sid),
                        "kind": category,
                        "value": pivot_value,
                    })

        depth_reached += 1
        if not next_frontier:
            break
        frontier = next_frontier

    return {
        "root_scan_id": root_scan_id,
        "depth_requested": depth,
        "max_nodes": max_nodes,
        "nodes": list(nodes_by_id.values()),
        "edges": edges,
        "stats": {
            "node_count": len(nodes_by_id),
            "edge_count": len(edges),
            "depth_reached": depth_reached,
            "truncated": truncated,
        },
    }


def _node_payload(
    *,
    scan_id: int,
    domain: str,
    verdict: str,
    scanned_at: str,
    is_root: bool,
) -> dict[str, Any]:
    """Build the per-node JSON shape consumed by the frontend."""
    return {
        "id": str(scan_id),       # Cytoscape requires string ids
        "scan_id": scan_id,
        "domain": domain,
        "verdict": verdict,
        "scanned_at": scanned_at,
        "type": "root" if is_root else "related",
    }


# ── Pivot extraction (parallels CrossScanCorrelator) ──────────


def _extract_pivots(recon: dict) -> dict[str, Any]:
    """
    Pull pivot attributes from a scan's recon results.

    Returns a dict with keys ip, asn, registrar, favicon_hash, slash24.
    Any field that couldn't be extracted is None — the caller treats
    None as "this pivot is inactive for this scan".

    This intentionally mirrors the extraction logic in CrossScanCorrelator
    so a scan's graph reflects exactly what its cross-scan correlation
    would have surfaced — same pivots, same results.
    """
    ip_intel = recon.get("ip_intel")
    whois = recon.get("whois")
    web = recon.get("web_recon")

    ip: str | None = None
    asn: str | None = None
    if ip_intel is not None and not ip_intel.error:
        ip_val = ip_intel.data.get("ip")
        if isinstance(ip_val, str) and ip_val:
            ip = ip_val
        geo = ip_intel.data.get("geolocation") or {}
        asn_val = geo.get("asn")
        if isinstance(asn_val, str) and asn_val:
            asn = asn_val

    registrar: str | None = None
    if whois is not None and not whois.error:
        reg = whois.data.get("registrar")
        if isinstance(reg, str) and reg:
            registrar = reg

    favicon_hash: int | None = None
    if web is not None and not web.error:
        favicon = web.data.get("favicon") or {}
        if isinstance(favicon, dict) and not favicon.get("error"):
            h = favicon.get("mmh3_hash")
            if isinstance(h, int):
                favicon_hash = h

    slash24 = CrossScanCorrelator._slash24_prefix(ip) if ip else None

    return {
        "ip": ip,
        "asn": asn,
        "registrar": registrar,
        "favicon_hash": favicon_hash,
        "slash24": slash24,
    }


def _pivot_display_value(category: str, pivots: dict[str, Any]) -> str:
    """Render the pivot attribute as a user-facing string for the edge."""
    if category == "ip":
        return pivots.get("ip") or ""
    if category == "asn":
        return pivots.get("asn") or ""
    if category == "registrar":
        return pivots.get("registrar") or ""
    if category == "favicon":
        fh = pivots.get("favicon_hash")
        return str(fh) if fh is not None else ""
    if category == "slash24":
        prefix = pivots.get("slash24")
        return f"{prefix}.0/24" if prefix else ""
    return ""
