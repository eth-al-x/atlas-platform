"""
atlas.api.routes.stats
Statistics and health endpoints.

GET /stats      Aggregate scan statistics
GET /health     API health check
"""

from __future__ import annotations

import asyncio
import logging
from functools import partial

from fastapi import APIRouter, Depends, Query

from atlas.api.dependencies import get_pipeline, get_repo
from atlas.api.schemas import HealthResponse, StatsResponse
from atlas.core.pipeline import AnalysisPipeline
from atlas.storage.db import ScanRepository

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Platform"])

# Recon tools available — populated at startup by the app factory
_RECON_TOOLS: list[str] = [
    "dns", "http_headers", "web_recon", "whois",
    "ip_intel", "crtsh", "urlscan", "subdomains",
]


@router.get(
    "/stats",
    response_model=StatsResponse,
    summary="Aggregate statistics",
    description=(
        "Returns scan counts by verdict, top flagged domains, "
        "and activity over the last 24 hours."
    ),
)
async def get_stats(
    days: int = Query(default=7, ge=1, le=365, description="Lookback window in days"),
    repo: ScanRepository = Depends(get_repo),
) -> StatsResponse:
    loop = asyncio.get_event_loop()
    stats = await loop.run_in_executor(
        None,
        partial(repo.get_stats, days),
    )
    return StatsResponse(stats=stats)


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Health check",
    description="Confirms the API is running and reports loaded components.",
)
async def health_check(
    pipeline: AnalysisPipeline = Depends(get_pipeline),
) -> HealthResponse:
    return HealthResponse(
        status="ok",
        version="2.0.0",
        tiers_loaded=len(pipeline.tier_names),
        recon_tools_available=_RECON_TOOLS,
    )
