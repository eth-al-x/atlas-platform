"""
atlas.core.models
Pydantic models used throughout the application.
Every tier, recon tool, and interface shares these structures.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Verdict(str, Enum):
    """Possible final verdicts for a scanned URL."""
    CLEAN = "Clean"
    LOW_RISK = "Low Risk"
    MEDIUM_RISK = "Medium Risk"
    HIGH_RISK = "High Risk"


class ScanSource(str, Enum):
    """Where a scan request originated."""
    CLI = "cli"
    API = "api"
    BATCH = "batch"
    SENSOR = "sensor"


# ── Tier Results ──────────────────────────────────────────────


class TierResult(BaseModel):
    """Standardized output from any analysis tier."""
    tier_name: str = ""
    display_name: str = ""
    flagged: bool = False
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    details: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None
    duration_ms: int = 0

    @property
    def passed(self) -> bool:
        return not self.flagged and self.error is None


# ── Scan Reports ─────────────────────────────────────────────


class ScanRequest(BaseModel):
    """Input for a scan operation."""
    url: str
    source: ScanSource = ScanSource.CLI
    skip_tiers: list[str] = Field(default_factory=list)


class ScanReport(BaseModel):
    """Complete output from the analysis pipeline."""
    id: int | None = None
    url: str
    domain: str
    final_verdict: Verdict = Verdict.CLEAN
    tier_results: list[TierResult] = Field(default_factory=list)
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    scan_duration_ms: int = 0
    source: ScanSource = ScanSource.CLI

    @property
    def is_risky(self) -> bool:
        return self.final_verdict in (Verdict.MEDIUM_RISK, Verdict.HIGH_RISK)

    @property
    def tiers_run(self) -> int:
        return len(self.tier_results)


# ── Recon Results ────────────────────────────────────────────


class ReconResult(BaseModel):
    """Standardized output from any recon tool."""
    recon_type: str
    domain: str
    data: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None
    performed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ── Statistics ───────────────────────────────────────────────


class ScanStats(BaseModel):
    """Aggregate statistics for the dashboard."""
    total_scans: int = 0
    high_risk: int = 0
    medium_risk: int = 0
    clean: int = 0
    top_flagged_domains: list[dict[str, Any]] = Field(default_factory=list)
    scans_last_24h: int = 0
