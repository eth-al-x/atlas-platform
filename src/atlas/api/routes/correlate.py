"""
atlas.api.routes.correlate
Correlation endpoints.

POST /correlate/{scan_id}   Run correlators against an existing scan

Note: the existing POST /investigate already includes correlations in its
response automatically. This endpoint is for re-running correlations
against a stored scan without re-doing the underlying scan + recon work.
"""

from __future__ import annotations

import asyncio
import logging
from functools import partial

from fastapi import APIRouter, Depends, HTTPException

from atlas.api.dependencies import get_atlas_config, get_repo
from atlas.api.schemas import CorrelateResponse
from atlas.core.config import AtlasConfig
from atlas.core.models import CorrelationContext
from atlas.correlate.pipeline import CorrelationPipeline
from atlas.storage.db import ScanRepository

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/correlate", tags=["Correlation"])


@router.post(
    "/{scan_id}",
    response_model=CorrelateResponse,
    summary="Re-run correlations against an existing scan",
    description=(
        "Runs the correlation pipeline against a previously-stored scan. "
        "Useful for re-analysis after new correlators are added, or for "
        "inspecting a scan's synthesis without paying recon cost again."
    ),
)
async def correlate_scan(
    scan_id: int,
    repo: ScanRepository = Depends(get_repo),
    config: AtlasConfig = Depends(get_atlas_config),
) -> CorrelateResponse:
    loop = asyncio.get_event_loop()
    report = await loop.run_in_executor(None, partial(repo.get_scan, scan_id))
    if report is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found.")

    pipeline = CorrelationPipeline(config=config)
    context = CorrelationContext(scan=report, recon={})

    correlations = await loop.run_in_executor(
        None,
        partial(pipeline.correlate, context),
    )

    # Persist for future retrieval
    await loop.run_in_executor(
        None,
        partial(repo.save_correlations, scan_id, correlations),
    )

    return CorrelateResponse(
        scan_id=scan_id,
        correlations=correlations,
    )
