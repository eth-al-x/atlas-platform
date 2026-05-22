"""
atlas.api.schemas
Pydantic models specific to the API layer.

The core models (ScanReport, TierResult, ReconResult) are reused directly
where possible. These schemas add API-specific wrappers: paginated list
responses, request bodies with API-only fields, and summary shapes that
omit heavy detail from list endpoints.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from atlas.core.models import ReconResult, ScanReport, ScanStats, Verdict


# ── Request bodies ────────────────────────────────────────────


class ScanRequestBody(BaseModel):
    """POST /scan request body."""

    url: str = Field(
        ...,
        description="The URL or domain to analyze.",
        examples=["https://example.com", "suspicious-domain.xyz"],
    )
    skip_tiers: list[str] = Field(
        default_factory=list,
        description="Tier names to skip (e.g. ['virustotal'] to avoid API calls).",
    )


class InvestigateRequestBody(BaseModel):
    """POST /investigate request body."""

    url: str = Field(..., description="The URL or domain to fully investigate.")
    skip_slow: bool = Field(
        default=False,
        description="Skip slow tools (urlscan.io) to return faster.",
    )
    include_subdomains: bool = Field(
        default=False,
        description="Include active subdomain enumeration (generates DNS traffic).",
    )


class ReconRequestBody(BaseModel):
    """POST /recon/{tool} request body."""

    target: str = Field(
        ...,
        description="Domain or URL to run recon against.",
        examples=["example.com", "https://example.com"],
    )


# ── Summary shapes (for list endpoints) ──────────────────────


class ScanSummary(BaseModel):
    """Lightweight scan record for list responses."""

    id: int
    url: str
    domain: str
    final_verdict: Verdict
    scanned_at: datetime
    scan_duration_ms: int

    @classmethod
    def from_row(cls, row: dict[str, Any]) -> "ScanSummary":
        return cls(
            id=row["id"],
            url=row["url"],
            domain=row["domain"],
            final_verdict=Verdict(row["final_verdict"]),
            scanned_at=datetime.fromisoformat(row["scanned_at"]),
            scan_duration_ms=row["scan_duration_ms"] or 0,
        )


# ── Paginated list responses ──────────────────────────────────


class PaginatedScans(BaseModel):
    """Paginated list of scan summaries."""

    items: list[ScanSummary]
    total: int
    limit: int
    offset: int
    has_more: bool


# ── API response envelope ─────────────────────────────────────


class ScanResponse(BaseModel):
    """Full scan report returned from POST /scan."""

    scan: ScanReport
    message: str = "Scan complete."


class InvestigateResponse(BaseModel):
    """Combined scan + recon results from POST /investigate."""

    scan: ScanReport
    recon: dict[str, ReconResult]
    message: str = "Investigation complete."


class ReconResponse(BaseModel):
    """Single recon tool result."""

    result: ReconResult
    message: str = "Recon complete."


class StatsResponse(BaseModel):
    """Aggregate platform statistics."""

    stats: ScanStats
    generated_at: datetime = Field(
        default_factory=lambda: __import__("datetime").datetime.now(
            __import__("datetime").timezone.utc
        )
    )


class HealthResponse(BaseModel):
    """API health check."""

    status: str = "ok"
    version: str = "2.0.0"
    tiers_loaded: int = 0
    recon_tools_available: list[str] = Field(default_factory=list)
