"""
atlas.api.routes.pivot
Pivot endpoints — find all scans related to a single piece of evidence.

GET /pivot/favicon/{favicon_hash}   Scans sharing a favicon hash
GET /pivot/subnet?cidr=...           Scans whose IP falls in a CIDR range

Pivots are direct queries against the scan history that take one piece of
evidence (a favicon hash, an IP, an ASN) and return every prior scan that
also has it. Where the cross-scan correlator surfaces pivots automatically
*for the current scan*, these endpoints let an analyst pivot from a single
known signal — like one they got from Shodan, a phishing report, or a
SIEM alert — without first having to scan a related domain.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
from functools import partial

from fastapi import APIRouter, Depends, HTTPException, Query

from atlas.api.dependencies import get_repo
from atlas.storage.db import ScanRepository

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/pivot", tags=["Pivot"])


@router.get(
    "/favicon/{favicon_hash}",
    summary="Find scans sharing a favicon hash",
    description=(
        "Given an MMH3 favicon hash (signed 32-bit int, Shodan-compatible), "
        "return every prior scan whose favicon hashed to the same value.\n\n"
        "Useful for brand-impersonation investigations: phishing kits "
        "almost universally copy the target brand's icon. Two domains "
        "sharing a hash are very likely either the same site, the same "
        "operator, or both impersonating the same brand."
    ),
)
async def pivot_favicon(
    favicon_hash: int,
    limit: int = Query(default=50, ge=1, le=200),
    repo: ScanRepository = Depends(get_repo),
) -> dict:
    loop = asyncio.get_event_loop()
    related = await loop.run_in_executor(
        None,
        partial(
            repo.find_related_scans,
            exclude_scan_id=-1,           # no scan to exclude — direct pivot
            favicon_hash=favicon_hash,
            limit_per_category=limit,
        ),
    )
    matches = related.get("favicon", [])
    return {
        "favicon_hash": favicon_hash,
        "match_count": len(matches),
        "matches": matches,
    }


@router.get(
    "/subnet",
    summary="Find scans with IPs in a subnet",
    description=(
        "Given an IPv4 CIDR, return every prior scan whose resolved IP "
        "falls within that range.\n\n"
        "Phishing campaigns often park multiple lookalike domains on "
        "neighboring IPs. /24 is the canonical 'same machine or rack' "
        "boundary; /27 and narrower often indicate shared-tenant VPS "
        "clusters or single operators; /16 catches whole hosting providers."
    ),
)
async def pivot_subnet(
    cidr: str = Query(
        ...,
        description="IPv4 CIDR (e.g. 203.0.113.0/24, 198.51.100.0/27)",
        examples=["203.0.113.0/24"],
    ),
    limit: int = Query(default=50, ge=1, le=200),
    repo: ScanRepository = Depends(get_repo),
) -> dict:
    # Validate CIDR before touching the DB so we can return a clean 400
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"invalid CIDR: {exc}")
    if network.version != 4:
        raise HTTPException(status_code=400, detail="IPv6 not supported (only IPv4 CIDRs)")

    loop = asyncio.get_event_loop()
    matches = await loop.run_in_executor(
        None,
        partial(repo.find_scans_in_subnet, str(network), None, None, limit),
    )
    return {
        "cidr": str(network),
        "match_count": len(matches),
        "address_count": network.num_addresses,
        "matches": matches,
    }
