"""
atlas.api.routes.watches
Watch list endpoints — domain monitoring with verdict-change detection.

GET    /watches          List all watch entries (with ?active=true filter)
POST   /watches          Add a domain to the watch list
GET    /watches/{id}     Get a single watch entry
DELETE /watches/{id}     Remove (deactivate) a watch entry
POST   /watches/run      Check all active watches and return alerts

These endpoints mirror the `atlas watch` CLI subcommand group. The same
WatchRepository backs both surfaces so changes from one are visible to the
other immediately.
"""

from __future__ import annotations

import asyncio
import logging
from functools import partial

from fastapi import APIRouter, Depends, HTTPException, Query

from atlas.api.dependencies import get_pipeline, get_repo, get_watch_repo
from atlas.api.schemas import WatchRequestBody, WatchRunRequestBody
from atlas.core.domain import extract_domain, normalize_url
from atlas.core.models import ScanRequest, ScanSource, WatchAlert, WatchEntry
from atlas.core.pipeline import AnalysisPipeline
from atlas.storage.db import ScanRepository, WatchRepository

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/watches", tags=["Monitoring"])


@router.get(
    "",
    response_model=list[WatchEntry],
    summary="List watched domains",
    description=(
        "Return all registered watch entries. Pass `active=true` to filter "
        "to only currently-monitored domains (removed watches are kept in "
        "the database but marked inactive)."
    ),
)
async def list_watches(
    active: bool = Query(default=False, description="If true, only return active watches"),
    watch_repo: WatchRepository = Depends(get_watch_repo),
) -> list[WatchEntry]:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None, partial(watch_repo.list_watches, active),
    )


@router.post(
    "",
    response_model=WatchEntry,
    summary="Add a domain to the watch list",
    description=(
        "Register a domain or URL for ongoing verdict monitoring. "
        "Idempotent: re-adding an existing domain re-activates it if "
        "it was previously removed."
    ),
    status_code=201,
)
async def add_watch(
    body: WatchRequestBody,
    watch_repo: WatchRepository = Depends(get_watch_repo),
) -> WatchEntry:
    target = body.target
    domain = extract_domain(target) if "/" in target else target.lower().strip()
    url = normalize_url(target if "/" in target else domain)

    loop = asyncio.get_event_loop()
    entry = await loop.run_in_executor(
        None, partial(watch_repo.add_watch, domain, url),
    )
    logger.info("API: added watch %d for %s", entry.id, domain)
    return entry


@router.get(
    "/{watch_id}",
    response_model=WatchEntry,
    summary="Get a single watch entry",
)
async def get_watch(
    watch_id: int,
    watch_repo: WatchRepository = Depends(get_watch_repo),
) -> WatchEntry:
    loop = asyncio.get_event_loop()
    entry = await loop.run_in_executor(
        None, partial(watch_repo.get_watch, watch_id),
    )
    if entry is None:
        raise HTTPException(status_code=404, detail=f"Watch {watch_id} not found.")
    return entry


@router.delete(
    "/{watch_id}",
    summary="Remove (deactivate) a watch",
    description=(
        "Soft delete: marks the watch as inactive but preserves its history. "
        "The same domain can be re-added later via POST /watches and will "
        "be re-activated rather than duplicated."
    ),
)
async def remove_watch(
    watch_id: int,
    watch_repo: WatchRepository = Depends(get_watch_repo),
) -> dict:
    loop = asyncio.get_event_loop()
    entry = await loop.run_in_executor(
        None, partial(watch_repo.get_watch, watch_id),
    )
    if entry is None:
        raise HTTPException(status_code=404, detail=f"Watch {watch_id} not found.")

    removed = await loop.run_in_executor(
        None, partial(watch_repo.remove_watch, watch_id),
    )
    return {"watch_id": watch_id, "domain": entry.domain, "removed": removed}


@router.post(
    "/run",
    response_model=list[WatchAlert],
    summary="Run all active watches and return alerts",
    description=(
        "Scan every active watched domain through the analysis pipeline, "
        "compare each new verdict to the previously stored one, and return "
        "the resulting alerts. Updates each watch's last_verdict and "
        "last_checked_at fields as a side effect.\n\n"
        "Recon is intentionally skipped here for speed — the goal is "
        "to surface verdict changes, not full investigation. To do a full "
        "investigate on a domain, hit POST /investigate."
    ),
)
async def run_watches(
    body: WatchRunRequestBody = WatchRunRequestBody(),
    watch_repo: WatchRepository = Depends(get_watch_repo),
    scan_repo: ScanRepository = Depends(get_repo),
    pipeline: AnalysisPipeline = Depends(get_pipeline),
) -> list[WatchAlert]:
    loop = asyncio.get_event_loop()
    entries = await loop.run_in_executor(
        None, partial(watch_repo.list_watches, True),
    )

    alerts: list[WatchAlert] = []
    for entry in entries:
        request = ScanRequest(url=entry.url, source=ScanSource.API)
        report = await loop.run_in_executor(
            None, partial(pipeline.analyze, request),
        )
        scan_id = await loop.run_in_executor(
            None, partial(scan_repo.save_scan, report),
        )
        report.id = scan_id

        alert = WatchAlert.build(
            watch=entry,
            new_verdict=report.final_verdict,
            scan_id=scan_id,
        )
        alerts.append(alert)

        await loop.run_in_executor(
            None,
            partial(
                watch_repo.update_after_check,
                entry.id,
                report.final_verdict.value,
                scan_id,
            ),
        )

    if body.changed_only:
        alerts = [a for a in alerts if a.changed or a.is_new]

    logger.info(
        "API: ran %d watch(es), %d alert(s)",
        len(entries),
        sum(1 for a in alerts if a.changed or a.is_new),
    )
    return alerts
