"""
atlas.core.pipeline
The central analysis pipeline. Orchestrates tiers in sequence,
handles early exits, and produces the final verdict.

This is the "brain" of ATLAS — every interface (CLI, API, dashboard)
calls into this to analyze a URL.
"""

from __future__ import annotations

import logging
import time

from atlas.core.config import AtlasConfig, get_config
from atlas.core.domain import extract_domain
from atlas.core.models import ScanReport, ScanRequest, TierResult, Verdict
from atlas.tiers.base import Tier
from atlas.tiers.local_blocklist import LocalBlocklistTier
from atlas.tiers.heuristics import HeuristicsTier
from atlas.tiers.dnsbl import DNSBLTier
from atlas.tiers.virustotal import VirusTotalTier


logger = logging.getLogger(__name__)


# ── Verdict determination ─────────────────────────────────────


def _determine_verdict(results: list[TierResult]) -> Verdict:
    """
    Determine the overall verdict from accumulated tier results.

    Rules:
        - Any tier with confidence >= 0.8 and flagged → High Risk
        - Any tier flagged → at least Medium Risk
        - No flags → Clean
    """
    if not results:
        return Verdict.CLEAN

    high_confidence_flags = [r for r in results if r.flagged and r.confidence >= 0.8]
    any_flags = [r for r in results if r.flagged]

    if high_confidence_flags:
        return Verdict.HIGH_RISK
    if any_flags:
        return Verdict.MEDIUM_RISK
    return Verdict.CLEAN


# ── The pipeline ──────────────────────────────────────────────


class AnalysisPipeline:
    """
    Configures and runs the tiered analysis sequence.

    Usage:
        pipeline = AnalysisPipeline()
        report = pipeline.analyze(ScanRequest(url="https://example.com"))
    """

    def __init__(self, config: AtlasConfig | None = None) -> None:
        self.config = config or get_config()
        self._tiers: list[Tier] = []
        self._setup_tiers()

    def _setup_tiers(self) -> None:
        """Initialize and register the analysis tiers in order."""
        # Tier 1: Local blocklist (fast, no network)
        blocklist = LocalBlocklistTier(self.config)
        blocklist.load()
        self._tiers.append(blocklist)

        # Tier 2: Heuristics (entropy + WHOIS)
        self._tiers.append(HeuristicsTier(self.config))

        # Tier 3: DNSBL (Spamhaus + SURBL)
        self._tiers.append(DNSBLTier(self.config))

        # Tier 4: VirusTotal (expensive, runs last)
        self._tiers.append(VirusTotalTier(self.config))

        # Future tiers (URLhaus, PhishTank, TLS, etc.)
        # are registered here as you build them:
        # self._tiers.append(URLhausTier(self.config))
        # self._tiers.append(VirusTotalTier(self.config))

        logger.info("Pipeline initialized with %d tiers: %s",
                     len(self._tiers),
                     ", ".join(t.display_name for t in self._tiers))

    @property
    def tier_names(self) -> list[str]:
        return [t.name for t in self._tiers]

    def analyze(self, request: ScanRequest) -> ScanReport:
        """
        Run the full analysis pipeline on a URL.

        Each tier runs in sequence. If a high-confidence flag is found
        and early_exit is enabled, later tiers are skipped.
        """
        start = time.perf_counter_ns()

        domain = extract_domain(request.url)
        logger.info("Analyzing %s (domain: %s)", request.url, domain)

        report = ScanReport(
            url=request.url,
            domain=domain,
            source=request.source,
        )

        for tier in self._tiers:
            # Skip tiers the caller explicitly excluded
            if tier.name in request.skip_tiers:
                logger.debug("Skipping tier %s (excluded by request)", tier.name)
                continue

            # Run the tier
            result = tier.check(domain, url=request.url)
            report.tier_results.append(result)

            # Determine the current verdict after this tier
            report.final_verdict = _determine_verdict(report.tier_results)

            # Early exit: if we already have a high-risk verdict and
            # the config says to stop, don't waste time on later tiers
            if (report.final_verdict == Verdict.HIGH_RISK
                    and self.config.analysis.early_exit_on_high_risk):
                logger.info("Early exit at tier %s (High Risk)", tier.display_name)
                break

        report.scan_duration_ms = (time.perf_counter_ns() - start) // 1_000_000

        logger.info("Verdict for %s: %s (%d ms, %d tiers run)",
                     request.url, report.final_verdict.value,
                     report.scan_duration_ms, report.tiers_run)

        return report
