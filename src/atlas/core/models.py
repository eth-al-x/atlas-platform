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
    correlations: list["CorrelationResult"] = Field(default_factory=list)
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


# ── Correlation Results ──────────────────────────────────────


class CorrelationContext(BaseModel):
    """
    Input bundle passed to correlators.

    A correlator reads completed scan + recon data and produces higher-order
    insights. It never re-runs the underlying tools.
    """
    scan: ScanReport
    recon: dict[str, ReconResult] = Field(default_factory=dict)


class CorrelationResult(BaseModel):
    """
    Standardized output from any correlator.

    Mirrors TierResult / ReconResult in spirit but carries synthesis findings
    rather than raw verdicts or raw data.
    """
    correlator_name: str = ""
    display_name: str = ""
    summary: str = ""                                  # One-line human-readable summary
    findings: list[dict[str, Any]] = Field(default_factory=list)  # Structured findings
    data: dict[str, Any] = Field(default_factory=dict)            # Tool-specific extras
    error: str | None = None
    duration_ms: int = 0


# ── Statistics ───────────────────────────────────────────────


class ScanStats(BaseModel):
    """Aggregate statistics for the dashboard."""
    total_scans: int = 0
    high_risk: int = 0
    medium_risk: int = 0
    low_risk: int = 0
    clean: int = 0
    top_flagged_domains: list[dict[str, Any]] = Field(default_factory=list)
    scans_last_24h: int = 0


# ── Watch Models ─────────────────────────────────────────────


# Severity order for comparing verdicts (higher = worse)
VERDICT_SEVERITY: dict[str, int] = {
    Verdict.CLEAN.value:       0,
    Verdict.LOW_RISK.value:    1,
    Verdict.MEDIUM_RISK.value: 2,
    Verdict.HIGH_RISK.value:   3,
}


class WatchEntry(BaseModel):
    """A domain registered for periodic verdict monitoring."""
    id: int | None = None
    domain: str
    url: str
    added_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_checked_at: datetime | None = None
    last_verdict: str | None = None       # Verdict.value or None (never checked)
    last_scan_id: int | None = None
    active: bool = True
    check_count: int = 0


class WatchAlert(BaseModel):
    """
    The result of checking a single watch entry.

    Produced after every `atlas watch run` check — whether or not the
    verdict changed. Consumers can filter by `changed` for alert-only views.
    """
    watch_id: int
    domain: str
    url: str
    previous_verdict: str | None   # None on the first ever check
    new_verdict: str
    scan_id: int
    changed: bool
    is_new: bool                   # True when this is the first check
    direction: str                 # "new" | "escalated" | "de-escalated" | "unchanged"

    @classmethod
    def build(
        cls,
        watch: WatchEntry,
        new_verdict: Verdict,
        scan_id: int,
    ) -> "WatchAlert":
        """
        Construct a WatchAlert by comparing a new verdict to the stored one.
        """
        previous = watch.last_verdict
        is_new = previous is None
        new_val = new_verdict.value
        changed = (previous != new_val)

        if is_new:
            direction = "new"
            changed = False   # first check: nothing "changed", there was no prior state
        elif not changed:
            direction = "unchanged"
        else:
            prev_sev = VERDICT_SEVERITY.get(previous or "", 0)
            new_sev = VERDICT_SEVERITY.get(new_val, 0)
            direction = "escalated" if new_sev > prev_sev else "de-escalated"

        return cls(
            watch_id=watch.id or 0,
            domain=watch.domain,
            url=watch.url,
            previous_verdict=previous,
            new_verdict=new_val,
            scan_id=scan_id,
            changed=changed,
            is_new=is_new,
            direction=direction,
        )
