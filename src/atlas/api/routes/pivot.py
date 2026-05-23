"""
atlas.api.routes.pivot
Pivot endpoints — find all scans related to a single piece of evidence.

GET /pivot/favicon/{favicon_hash}   Scans sharing a favicon hash

Pivots are direct queries against the scan history that take one piece of
evidence (a favicon hash, an IP, an ASN) and return every prior scan that
also has it. Where the cross-scan correlator surfaces pivots automatically
*for the current scan*, these endpoints let an analyst pivot from a single
known signal — like one they got from Shodan, a phishing report, or a
SIEM alert — without first having to scan a related domain.
"""

from __future__ import annotations

import asyncio
import logging
from functools import partial

from fastapi import APIRouter, Depends, Query

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
