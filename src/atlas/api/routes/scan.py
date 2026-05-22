"""
atlas.api.routes.scan
Scan-related API endpoints.

POST /scan          Submit a URL for threat analysis
GET  /scans         List recent scans (paginated)
GET  /scans/{id}    Get a single scan report by ID
DELETE /scans/{id}  Delete a scan record
"""

from __future__ import annotations

import asyncio
import logging
from functools import partial

from fastapi import APIRouter, Depends, HTTPException, Query

from atlas.api.dependencies import get_pipeline, get_repo
from atlas.api.schemas import (
    PaginatedScans,
    ScanRequestBody,
    ScanResponse,
    ScanSummary,
)
from atlas.core.models import ScanRequest, ScanSource
from atlas.core.pipeline import AnalysisPipeline
from atlas.storage.db import ScanRepository

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/scan", tags=["Analysis"])


@router.post(
    "",
    response_model=ScanResponse,
    summary="Analyze a URL",
    description=(
        "Submit a URL through ATLAS's tiered threat-analysis pipeline. "
        "Returns a verdict (Clean / Medium Risk / High Risk) with per-tier details. "
        "Results are persisted to the local database."
    ),
)
async def submit_scan(
    body: ScanRequestBody,
    pipeline: AnalysisPipeline = Depends(get_pipeline),
    repo: ScanRepository = Depends(get_repo),
) -> ScanResponse:
    """Run the analysis pipeline and persist the result."""
    request = ScanRequest(
        url=body.url,
        source=ScanSource.API,
        skip_tiers=body.skip_tiers,
    )

    # The pipeline is synchronous (blocking I/O). Run it in a thread pool
    # so it doesn't block the event loop for other concurrent requests.
    loop = asyncio.get_event_loop()
    report = await loop.run_in_executor(
        None,
        partial(pipeline.analyze, request),
    )

    # Persist and attach the DB id to the report
    scan_id = repo.save_scan(report)
    report.id = scan_id

    logger.info("API scan %d: %s → %s", scan_id, body.url, report.final_verdict.value)

    return ScanResponse(scan=report)


@router.get(
    "s",
    response_model=PaginatedScans,
    summary="List recent scans",
    description="Returns a paginated list of scan summaries, newest first.",
)
async def list_scans(
    limit: int = Query(default=20, ge=1, le=100, description="Results per page"),
    offset: int = Query(default=0, ge=0, description="Pagination offset"),
    repo: ScanRepository = Depends(get_repo),
) -> PaginatedScans:
    """Paginated list of recent scans."""
    loop = asyncio.get_event_loop()
    rows = await loop.run_in_executor(
        None,
        partial(repo.list_scans, limit + 1, offset),  # fetch one extra to detect has_more
    )

    has_more = len(rows) > limit
    items = [ScanSummary.from_row(r) for r in rows[:limit]]

    return PaginatedScans(
        items=items,
        total=len(items),
        limit=limit,
        offset=offset,
        has_more=has_more,
    )


@router.get(
    "s/{scan_id}",
    response_model=ScanResponse,
    summary="Get a scan by ID",
    description="Retrieve the full scan report for a specific scan ID.",
)
async def get_scan(
    scan_id: int,
    repo: ScanRepository = Depends(get_repo),
) -> ScanResponse:
    """Retrieve a single scan report."""
    loop = asyncio.get_event_loop()
    report = await loop.run_in_executor(
        None,
        partial(repo.get_scan, scan_id),
    )

    if report is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found.")

    return ScanResponse(scan=report)
